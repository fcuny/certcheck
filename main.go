package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"time"
)

type OutputFormat string

const (
	FormatShort OutputFormat = "short"
	FormatLong  OutputFormat = "long"
	FormatJSON  OutputFormat = "json"
)

type Config struct {
	Domain   string
	Port     int
	Insecure bool
	Format   OutputFormat
	Timeout  time.Duration
	WarnDays int
}

func main() {
	var config Config
	var formatStr string
	var showVersion bool

	flag.StringVar(&config.Domain, "domain", "", "Domain to check (required)")
	flag.IntVar(&config.Port, "port", 443, "Port to check")
	flag.BoolVar(&config.Insecure, "insecure", false, "Accept invalid certificate")
	flag.StringVar(&formatStr, "format", "short", "Output format (short|long|json)")
	flag.DurationVar(&config.Timeout, "timeout", 10*time.Second, "Connection timeout")
	flag.IntVar(&config.WarnDays, "warn-days", 0, "Exit with status 2 if certificate expires within this many days (0 disables)")
	flag.BoolVar(&showVersion, "version", false, "Print the version and the Go toolchain it was built with, then exit")
	flag.Parse()

	if showVersion {
		info, _ := debug.ReadBuildInfo() // nil when the binary has no build info
		fmt.Println(versionString(info))
		os.Exit(0)
	}

	if config.Domain == "" {
		if len(flag.Args()) == 0 {
			fmt.Fprintf(os.Stderr, "Error: domain is required\n")
			flag.Usage()
			os.Exit(1)
		}
		config.Domain = flag.Args()[0]
	}

	switch formatStr {
	case "short":
		config.Format = FormatShort
	case "long":
		config.Format = FormatLong
	case "json":
		config.Format = FormatJSON
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid format '%s', must be 'short', 'long' or 'json'\n", formatStr)
		os.Exit(1)
	}

	cert, err := getCertificate(config.Domain, config.Port, config.Insecure, nil, config.Timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	printCertificate(cert, config.Format)

	remainingDays := int(time.Until(cert.NotAfter).Hours() / 24)
	os.Exit(exitCodeForExpiry(remainingDays, config.WarnDays))
}

// versionString describes the build from the information the Go toolchain
// embeds in every binary, so it needs no -ldflags. The module version is the
// tag for `go install ...@vX.Y.Z`, or a pseudo-version with the commit (and
// "+dirty" for uncommitted changes) for builds from a checkout. The Go version
// matters too: it decides which crypto/x509 fixes, such as distrusted
// intermediates, the binary has.
func versionString(info *debug.BuildInfo) string {
	if info == nil {
		return fmt.Sprintf("certcheck unknown built with %s", runtime.Version())
	}

	version := info.Main.Version
	if version == "" || version == "(devel)" {
		version = "(devel)"
		var revision string
		var modified bool
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
		if revision != "" {
			if len(revision) > 12 {
				revision = revision[:12]
			}
			version = revision
			if modified {
				version += "+dirty"
			}
		}
	}

	goVersion := info.GoVersion
	if goVersion == "" {
		goVersion = runtime.Version()
	}
	return fmt.Sprintf("certcheck %s built with %s", version, goVersion)
}

func exitCodeForExpiry(remainingDays int, warnDays int) int {
	if warnDays > 0 && remainingDays <= warnDays {
		return 2
	}
	return 0
}

// getCertificate returns the leaf certificate presented by domain:port. It
// verifies the chain against roots, or against the system roots when roots is
// nil, unless insecure is set.
func getCertificate(domain string, port int, insecure bool, roots *x509.CertPool, timeout time.Duration) (*x509.Certificate, error) {
	address := fmt.Sprintf("%s:%d", domain, port)

	tlsConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: insecure,
		RootCAs:            roots,
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			// Log the error but don't override the main function's return value
			fmt.Fprintf(os.Stderr, "warning: failed to close connection: %v\n", closeErr)
		}
	}()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate found for %s", domain)
	}

	return certs[0], nil
}

func printCertificate(cert *x509.Certificate, format OutputFormat) {
	switch format {
	case FormatShort:
		printShort(cert)
	case FormatLong:
		printLong(cert)
	case FormatJSON:
		printJSON(cert)
	}
}

func printShort(cert *x509.Certificate) {
	remaining := time.Until(cert.NotAfter)

	commonName := getCommonName(cert)

	if remaining >= 0 {
		days := int(remaining.Hours() / 24)
		fmt.Printf("%s: %s (%d days left)\n",
			commonName,
			cert.NotAfter.Format(time.RFC1123Z),
			days)
	} else {
		days := int(-remaining.Hours() / 24)
		fmt.Printf("%s: %s (it expired %d days ago)\n",
			commonName,
			cert.NotAfter.Format(time.RFC1123Z),
			days)
	}
}

func printLong(cert *x509.Certificate) {
	remaining := time.Until(cert.NotAfter)
	validityDuration := cert.NotAfter.Sub(cert.NotBefore)

	fmt.Println("certificate")
	fmt.Printf(" version: %d\n", cert.Version)
	fmt.Printf(" serial: %s\n", cert.SerialNumber.String())
	fmt.Printf(" subject: %s\n", cert.Subject.String())
	fmt.Printf(" issuer: %s\n", cert.Issuer.String())

	fmt.Println(" validity")
	fmt.Printf("  not before    : %s\n", cert.NotBefore.Format(time.RFC1123Z))
	fmt.Printf("  not after     : %s\n", cert.NotAfter.Format(time.RFC1123Z))
	fmt.Printf("  validity days : %d\n", int(validityDuration.Hours()/24))
	fmt.Printf("  remaining days: %d\n", int(remaining.Hours()/24))

	fmt.Println(" SANs:")
	printSANs(cert)
}

type CertificateInfo struct {
	CommonName     string    `json:"commonName"`
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	SerialNumber   string    `json:"serialNumber"`
	Version        int       `json:"version"`
	NotBefore      time.Time `json:"notBefore"`
	NotAfter       time.Time `json:"notAfter"`
	ValidityDays   int       `json:"validityDays"`
	RemainingDays  int       `json:"remainingDays"`
	Expired        bool      `json:"expired"`
	DNSNames       []string  `json:"dnsNames,omitempty"`
	IPAddresses    []string  `json:"ipAddresses,omitempty"`
	EmailAddresses []string  `json:"emailAddresses,omitempty"`
	URIs           []string  `json:"uris,omitempty"`
}

func buildCertificateInfo(cert *x509.Certificate) CertificateInfo {
	remaining := time.Until(cert.NotAfter)
	validityDuration := cert.NotAfter.Sub(cert.NotBefore)

	ipAddresses := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ipAddresses[i] = ip.String()
	}

	uris := make([]string, len(cert.URIs))
	for i, uri := range cert.URIs {
		uris[i] = uri.String()
	}

	return CertificateInfo{
		CommonName:     getCommonName(cert),
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		SerialNumber:   cert.SerialNumber.String(),
		Version:        cert.Version,
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		ValidityDays:   int(validityDuration.Hours() / 24),
		RemainingDays:  int(remaining.Hours() / 24),
		Expired:        remaining < 0,
		DNSNames:       cert.DNSNames,
		IPAddresses:    ipAddresses,
		EmailAddresses: cert.EmailAddresses,
		URIs:           uris,
	}
}

func printJSON(cert *x509.Certificate) {
	info := buildCertificateInfo(cert)

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to marshal certificate info: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(data))
}

func getCommonName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return "<no name>"
}

func printSANs(cert *x509.Certificate) {
	// DNS names
	for _, name := range cert.DNSNames {
		fmt.Printf("  DNS:%s\n", name)
	}

	// IP addresses
	for _, ip := range cert.IPAddresses {
		fmt.Printf("  IP address:%s\n", ip.String())
	}

	// Email addresses
	for _, email := range cert.EmailAddresses {
		fmt.Printf("  Email:%s\n", email)
	}

	// URIs
	for _, uri := range cert.URIs {
		fmt.Printf("  URI:%s\n", uri.String())
	}
}
