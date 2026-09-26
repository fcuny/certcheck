package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestGetCertificateTimeout(t *testing.T) {
	start := time.Now()
	_, err := getCertificate("10.255.255.1", 443, false, 200*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error dialing a non-routable address, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("getCertificate took %s, expected it to time out quickly", elapsed)
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
