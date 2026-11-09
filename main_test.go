package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testHost       = "127.0.0.1"
	testOtherHost  = "127.0.0.2"
	testCommonName = "certcheck-test"

	// runMainEnv makes the test binary behave as the certcheck CLI, so tests can
	// observe real flag parsing, stdout and exit codes.
	runMainEnv = "CERTCHECK_TEST_RUN_MAIN"
)

// The half-day offsets keep the whole-day counts in the CLI output stable while
// a test runs.
var (
	validUntil   = time.Now().Add(30*24*time.Hour + 12*time.Hour)
	expiredSince = time.Now().Add(-30*24*time.Hour - 12*time.Hour)
)

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// startTLSServer serves a self-signed certificate on the loopback interface. It
// returns the port and a pool that trusts the certificate.
func startTLSServer(t *testing.T, notAfter time.Time, san string) (int, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testCommonName},
		NotBefore:             notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP(san)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	listener, err := tls.Listen("tcp", net.JoinHostPort(testHost, "0"), &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = conn.Close() }()
				// Reading drives the handshake, then waits for the client to hang up.
				_, _ = io.Copy(io.Discard, conn)
			})
		}
	})
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})

	return listener.Addr().(*net.TCPAddr).Port, roots
}

func isUnknownAuthority(err error) bool {
	var target x509.UnknownAuthorityError
	return errors.As(err, &target)
}

func isExpired(err error) bool {
	var target x509.CertificateInvalidError
	return errors.As(err, &target) && target.Reason == x509.Expired
}

func isHostnameMismatch(err error) bool {
	var target x509.HostnameError
	return errors.As(err, &target)
}

func TestGetCertificateVerification(t *testing.T) {
	tests := []struct {
		name        string
		notAfter    time.Time
		san         string
		trusted     bool // pass the server's certificate as roots, otherwise use system roots
		insecure    bool
		wantErr     func(error) bool // nil means the call must succeed
		wantExpired bool
	}{
		{name: "untrusted chain fails", notAfter: validUntil, san: testHost, wantErr: isUnknownAuthority},
		{name: "untrusted chain with insecure succeeds", notAfter: validUntil, san: testHost, insecure: true},
		{name: "trusted chain succeeds", notAfter: validUntil, san: testHost, trusted: true},
		{name: "expired certificate fails", notAfter: expiredSince, san: testHost, trusted: true, wantErr: isExpired},
		{name: "expired certificate with insecure is reported as expired", notAfter: expiredSince, san: testHost, insecure: true, wantExpired: true},
		{name: "hostname mismatch fails", notAfter: validUntil, san: testOtherHost, trusted: true, wantErr: isHostnameMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, serverRoots := startTLSServer(t, tt.notAfter, tt.san)
			var roots *x509.CertPool
			if tt.trusted {
				roots = serverRoots
			}

			cert, err := getCertificate(testHost, port, tt.insecure, roots, 5*time.Second)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected a verification error, got nil")
				}
				if !tt.wantErr(err) {
					t.Fatalf("unexpected error type: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cert.Subject.CommonName != testCommonName {
				t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, testCommonName)
			}
			if got := buildCertificateInfo(cert).Expired; got != tt.wantExpired {
				t.Errorf("Expired = %v, want %v", got, tt.wantExpired)
			}
		})
	}
}

// The listener never accepts or writes, so the handshake stalls until the
// timeout fires. The timeout covers the connect and the handshake together.
func TestGetCertificateTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", net.JoinHostPort(testHost, "0"))
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port

	done := make(chan error, 1)
	go func() {
		_, err := getCertificate(testHost, port, false, nil, 100*time.Millisecond)
		done <- err
	}()

	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("getCertificate did not honor its timeout")
	}

	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a timeout error, got %v", err)
	}
}

func runCLI(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locating test binary: %v", err)
	}
	cmd := exec.Command(executable, args...)
	cmd.Env = append(os.Environ(), runMainEnv+"=1")
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running CLI: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), cmd.ProcessState.ExitCode()
}

func TestCLI(t *testing.T) {
	validPort, _ := startTLSServer(t, validUntil, testHost)
	expiredPort, _ := startTLSServer(t, expiredSince, testHost)

	tests := []struct {
		name       string
		args       []string
		wantExit   int
		wantStdout []string
		wantStderr string
	}{
		{
			name:       "positional domain with default short format",
			args:       []string{"-insecure", "-port", strconv.Itoa(validPort), testHost},
			wantStdout: []string{testCommonName + ":", "(30 days left)"},
		},
		{
			name:       "domain flag with short format on expired certificate",
			args:       []string{"-domain", testHost, "-port", strconv.Itoa(expiredPort), "-insecure"},
			wantStdout: []string{"(it expired 30 days ago)"},
		},
		{
			name:       "domain flag with long format on expired certificate",
			args:       []string{"-domain", testHost, "-port", strconv.Itoa(expiredPort), "-insecure", "-format", "long"},
			wantStdout: []string{"remaining days: -30", "IP address:" + testHost},
		},
		{
			name:       "json format on expired certificate",
			args:       []string{"-domain", testHost, "-port", strconv.Itoa(expiredPort), "-insecure", "-format", "json"},
			wantStdout: []string{`"expired": true`, `"commonName": "` + testCommonName + `"`},
		},
		{
			name:       "untrusted certificate exits 1 without insecure",
			args:       []string{"-port", strconv.Itoa(validPort), testHost},
			wantExit:   1,
			wantStderr: fmt.Sprintf("failed to connect to %s:%d", testHost, validPort),
		},
		{
			// -version must not require a domain or open a connection.
			name:       "version flag prints version and exits 0",
			args:       []string{"-version"},
			wantStdout: []string{"certcheck ", " built with " + runtime.Version() + "\n"},
		},
		{
			name:       "version flag ignores the domain",
			args:       []string{"-version", "-port", strconv.Itoa(validPort), testHost},
			wantStdout: []string{" built with " + runtime.Version()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, exitCode := runCLI(t, tt.args...)

			if exitCode != tt.wantExit {
				t.Fatalf("exit code = %d, want %d\nstdout: %s\nstderr: %s", exitCode, tt.wantExit, stdout, stderr)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout missing %q:\n%s", want, stdout)
				}
			}
			if tt.wantExit != 0 && stdout != "" {
				t.Errorf("expected empty stdout on failure, got:\n%s", stdout)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr missing %q:\n%s", tt.wantStderr, stderr)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	const rev = "ffb84d0e02c692abae48e91feb5dca65bfc94773"
	vcs := func(revision, modified string) []debug.BuildSetting {
		return []debug.BuildSetting{
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: revision},
			{Key: "vcs.modified", Value: modified},
		}
	}

	tests := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{
			name: "tagged install",
			info: &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Version: "v0.1.0"}},
			want: "certcheck v0.1.0 built with go1.27.3",
		},
		{
			name: "pseudo-version from a dirty checkout keeps its own commit",
			info: &debug.BuildInfo{
				GoVersion: "go1.27.3",
				Main:      debug.Module{Version: "v0.0.0-20261109171944-ffb84d0e02c6+dirty"},
				Settings:  vcs(rev, "true"),
			},
			want: "certcheck v0.0.0-20261109171944-ffb84d0e02c6+dirty built with go1.27.3",
		},
		{
			name: "devel build falls back to the commit",
			info: &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Version: "(devel)"}, Settings: vcs(rev, "false")},
			want: "certcheck ffb84d0e02c6 built with go1.27.3",
		},
		{
			name: "devel build marks uncommitted changes",
			info: &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Version: "(devel)"}, Settings: vcs(rev, "true")},
			want: "certcheck ffb84d0e02c6+dirty built with go1.27.3",
		},
		{
			name: "devel build without VCS information",
			info: &debug.BuildInfo{GoVersion: "go1.27.3", Main: debug.Module{Version: "(devel)"}},
			want: "certcheck (devel) built with go1.27.3",
		},
		{
			name: "empty version and Go version",
			info: &debug.BuildInfo{},
			want: "certcheck (devel) built with " + runtime.Version(),
		},
		{
			name: "no build information",
			info: nil,
			want: "certcheck unknown built with " + runtime.Version(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionString(tt.info); got != tt.want {
				t.Errorf("versionString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExitCodeForExpiry(t *testing.T) {
	tests := []struct {
		name          string
		remainingDays int
		warnDays      int
		want          int
	}{
		{"disabled always zero", 1, 0, 0},
		{"disabled even when expired", -30, 0, 0},
		{"well above threshold", 30, 5, 0},
		{"exactly at threshold", 5, 5, 2},
		{"below threshold", 3, 5, 2},
		{"expired", -10, 5, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exitCodeForExpiry(tt.remainingDays, tt.warnDays)
			if got != tt.want {
				t.Errorf("exitCodeForExpiry(%d, %d) = %d, want %d", tt.remainingDays, tt.warnDays, got, tt.want)
			}
		})
	}
}

func TestBuildCertificateInfo(t *testing.T) {
	notBefore := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(0, 0, 30)

	cert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "example.com"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"example.com", "www.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("192.0.2.1")},
	}

	info := buildCertificateInfo(cert)

	if info.CommonName != "example.com" {
		t.Errorf("CommonName = %q, want %q", info.CommonName, "example.com")
	}
	if info.SerialNumber != "12345" {
		t.Errorf("SerialNumber = %q, want %q", info.SerialNumber, "12345")
	}
	if info.Version != 3 {
		t.Errorf("Version = %d, want %d", info.Version, 3)
	}
	if info.ValidityDays != 30 {
		t.Errorf("ValidityDays = %d, want %d", info.ValidityDays, 30)
	}
	if !info.Expired {
		t.Errorf("Expired = %v, want %v", info.Expired, true)
	}
	if len(info.DNSNames) != 2 || info.DNSNames[0] != "example.com" || info.DNSNames[1] != "www.example.com" {
		t.Errorf("DNSNames = %v, want %v", info.DNSNames, []string{"example.com", "www.example.com"})
	}
	if len(info.IPAddresses) != 1 || info.IPAddresses[0] != "192.0.2.1" {
		t.Errorf("IPAddresses = %v, want %v", info.IPAddresses, []string{"192.0.2.1"})
	}
}

func TestBuildCertificateInfoNoCommonName(t *testing.T) {
	cert := &x509.Certificate{
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	info := buildCertificateInfo(cert)

	if info.CommonName != "<no name>" {
		t.Errorf("CommonName = %q, want %q", info.CommonName, "<no name>")
	}
	if info.Expired {
		t.Errorf("Expired = %v, want %v", info.Expired, false)
	}
}
