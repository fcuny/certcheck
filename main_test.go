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
