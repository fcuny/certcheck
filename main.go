package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"
)

type OutputFormat string

const (
	FormatShort OutputFormat = "short"
	FormatLong  OutputFormat = "long"
)

type Config struct {
	Domain   string
	Port     int
	Insecure bool
	Format   OutputFormat
}

func main() {
	var config Config
	var formatStr string

	flag.StringVar(&config.Domain, "domain", "", "Domain to check (required)")
	flag.IntVar(&config.Port, "port", 443, "Port to check")
	flag.BoolVar(&config.Insecure, "insecure", false, "Accept invalid certificate")
	flag.StringVar(&formatStr, "format", "short", "Output format (short|long)")
	flag.Parse()

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
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid format '%s', must be 'short' or 'long'\n", formatStr)
		os.Exit(1)
	}

	cert, err := getCertificate(config.Domain, config.Port, config.Insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	printCertificate(cert, config.Format)
}

func getCertificate(domain string, port int, insecure bool) (*x509.Certificate, error) {
	address := fmt.Sprintf("%s:%d", domain, port)

	tlsConfig := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: insecure,
	}

	conn, err := tls.Dial("tcp", address, tlsConfig)
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
