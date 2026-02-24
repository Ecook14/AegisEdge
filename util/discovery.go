// Package util: discovery.go auto-discovers trusted proxy IPs from local
// security tools (CSF, cPHulk, iptables) at startup.
// Linux-only sources are skipped silently on other platforms.
package util

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// DiscoverTrustedProxies collects whitelisted IPs from all local security
// tools and returns a deduplicated slice of valid IP/CIDR strings.
//
// Sources (Linux only):
//   - CSF:     /etc/csf/csf.allow
//   - cPHulk:  /usr/local/cpanel/etc/hulkd/whitelist
//   - iptables ACCEPT rules in the INPUT chain
func DiscoverTrustedProxies() []string {
	if runtime.GOOS != "linux" {
		return nil
	}

	seen := make(map[string]struct{})
	var results []string

	add := func(entry string) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return
		}
		// Validate: must be a parseable IP or CIDR.
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return
			}
		} else {
			if net.ParseIP(entry) == nil {
				return
			}
		}
		if _, exists := seen[entry]; !exists {
			seen[entry] = struct{}{}
			results = append(results, entry)
		}
	}

	for _, entry := range readCSFAllow() {
		add(entry)
	}
	for _, entry := range readCPHulkWhitelist() {
		add(entry)
	}
	for _, entry := range readIptablesAccept() {
		add(entry)
	}

	return results
}

// readCSFAllow parses /etc/csf/csf.allow.
// Lines starting with # are comments. IP can have optional CIDR suffix.
// Format examples:
//   1.2.3.4  # some comment
//   10.0.0.0/8
func readCSFAllow() []string {
	return parseIPFile("/etc/csf/csf.allow")
}

// readCPHulkWhitelist parses cPHulk's whitelist file.
// Format is one IP per line, optional comments.
func readCPHulkWhitelist() []string {
	// cPHulk can store its whitelist in either location depending on version.
	paths := []string{
		"/usr/local/cpanel/etc/hulkd/whitelist",
		"/var/cpanel/hulkd/whitelist",
	}
	for _, p := range paths {
		if ips := parseIPFile(p); len(ips) > 0 {
			return ips
		}
	}
	return nil
}

// readIptablesAccept extracts source IPs from iptables INPUT ACCEPT rules.
// This catches any IP that has been statically permitted via iptables directly.
func readIptablesAccept() []string {
	out, err := exec.Command("iptables", "-n", "-L", "INPUT").Output()
	if err != nil {
		return nil
	}

	var ips []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		// iptables -n -L line format:
		// ACCEPT     tcp  --  203.0.113.5          0.0.0.0/0  ...
		if !strings.HasPrefix(line, "ACCEPT") {
			continue
		}
		fields := strings.Fields(line)
		// fields[3] is the source address
		if len(fields) >= 4 {
			src := fields[3]
			// Skip wildcard 0.0.0.0/0 — that would trust everything.
			if src == "0.0.0.0/0" || src == "::/0" || src == "anywhere" {
				continue
			}
			ips = append(ips, src)
		}
	}
	return ips
}

// parseIPFile reads a file and returns all IPs/CIDRs found on non-comment lines.
func parseIPFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var ips []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Strip inline comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Take the first whitespace-delimited token (the IP/CIDR)
		token := strings.Fields(line)[0]
		ips = append(ips, token)
	}
	return ips
}
