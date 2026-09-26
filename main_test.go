package main

import (
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
