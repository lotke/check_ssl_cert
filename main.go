/*
check_ssl_cert - Icinga check for HTTPS certificate validity
Based on github.com/rapidloop/certchk
Copyright (c) 2018 lotke

Licensed under the MIT License. See the original license for details.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/dustin/go-humanize"
)

func checkCertificate(server string, warnDays, critDays, port int, ipAddress, dnsServer string, timeout time.Duration) {
	// Use server as IP address if not specified
	if ipAddress == "" {
		ipAddress = server
	}

	target := fmt.Sprintf("%s:%d", ipAddress, port)

	// Set up dialer with configurable timeout
	dialer := &net.Dialer{Timeout: timeout}

	// Configure custom DNS resolver if a DNS server is specified
	if dnsServer != "" {
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
		// Resolve the IP address using the custom DNS server
		addrs, err := dialer.Resolver.LookupHost(context.Background(), server)
		if err != nil {
			fmt.Printf("SSL_CERT CRITICAL %s: failed to resolve %s using DNS server %s: %v\n",
				server, server, dnsServer, err)
			os.Exit(2)
		}
		if len(addrs) == 0 {
			fmt.Printf("SSL_CERT CRITICAL %s: no IP addresses resolved for %s using DNS server %s\n",
				server, server, dnsServer)
			os.Exit(2)
		}
		// Use the first resolved IP address if ipAddress is not explicitly provided
		if ipAddress == server {
			ipAddress = addrs[0]
			target = fmt.Sprintf("%s:%d", ipAddress, port)
		}
	}

	// Establish TLS connection with support for older SSL/TLS versions
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		ServerName:         server,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionSSL30, // Allow all versions from SSLv3
	})
	if err != nil {
		// Check if the error is a timeout
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Printf("SSL_CERT CRITICAL %s: TCP connection timeout after %v to %s\n",
				server, timeout, target)
		} else {
			fmt.Printf("SSL_CERT CRITICAL %s: failed to connect to %s: %v\n",
				server, target, err)
		}
		os.Exit(2)
	}
	defer conn.Close()

	// Verify hostname
	if err := conn.VerifyHostname(server); err != nil {
		fmt.Printf("SSL_CERT CRITICAL %s: hostname verification failed for %s: %v\n",
			server, target, err)
		os.Exit(2)
	}

	// Check certificate expiration
	cert := conn.ConnectionState().PeerCertificates[0]
	issuer := cert.Issuer
	expires := cert.NotAfter
	daysUntilExpiry := time.Until(expires).Hours() / 24

	// Report negotiated TLS version for informational purposes
	tlsVersion := tlsVersionToString(conn.ConnectionState().Version)
	fmt.Printf("SSL_CERT INFO %s: negotiated TLS version %s\n", server, tlsVersion)

	switch {
	case daysUntilExpiry <= float64(critDays):
		fmt.Printf("SSL_CERT CRITICAL %s: valid, expires on %s (%s), issuer: %v\n",
			server, expires.Format("2006-01-02"), humanize.Time(expires), issuer)
		os.Exit(2)
	case daysUntilExpiry <= float64(warnDays):
		fmt.Printf("SSL_CERT WARNING %s: valid, expires on %s (%s), issuer: %v\n",
			server, expires.Format("2006-01-02"), humanize.Time(expires), issuer)
		os.Exit(1)
	default:
		fmt.Printf("SSL_CERT OK %s: valid, expires on %s (%s), issuer: %v\n",
			server, expires.Format("2006-01-02"), humanize.Time(expires), issuer)
		os.Exit(0)
	}
}

// tlsVersionToString converts a TLS version number to a human-readable string
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%x)", version)
	}
}

func main() {
	// Define command-line flags
	critDays := flag.Int("c", 7, "critical threshold in days")
	warnDays := flag.Int("w", 14, "warning threshold in days")
	port := flag.Int("p", 443, "port number")
	hostname := flag.String("H", "localhost", "hostname to check")
	ipAddress := flag.String("I", "", "IP address (optional, defaults to hostname)")
	timeoutSec := flag.Int("t", 30, "TCP connection timeout in seconds")
	dnsServer := flag.String("d", "", "custom DNS server (e.g., 8.8.8.8:53)")

	flag.Parse()

	// Validate flags
	if *warnDays <= *critDays {
		fmt.Fprintln(os.Stderr, "Error: warning threshold must be greater than critical threshold")
		os.Exit(1)
	}
	if *timeoutSec <= 0 {
		fmt.Fprintln(os.Stderr, "Error: timeout must be a positive number of seconds")
		os.Exit(1)
	}
	if *dnsServer != "" {
		// Basic validation of DNS server format (host:port)
		if _, _, err := net.SplitHostPort(*dnsServer); err != nil {
			fmt.Fprintln(os.Stderr, "Error: invalid DNS server format, expected host:port (e.g., 8.8.8.8:53)")
			os.Exit(1)
		}
	}

	// Convert timeout to duration
	timeout := time.Duration(*timeoutSec) * time.Second

	// Perform certificate check
	checkCertificate(*hostname, *warnDays, *critDays, *port, *ipAddress, *dnsServer, timeout)
}
