package filter

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"aegisedge/logger"
)

// HardenOS applies kernel-level protections against common network attacks.
func HardenOS() {
	if runtime.GOOS == "windows" {
		hardenWindows()
	} else if runtime.GOOS == "linux" {
		hardenLinux()
	}
}

// BlockIPKernel blocks an IP address at the OS firewall level (L3).
func BlockIPKernel(ip string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// netsh advfirewall firewall add rule name="AegisBlock_1.2.3.4" dir=in action=block remoteip=1.2.3.4
		ruleName := fmt.Sprintf("AegisBlock_%s", ip)
		cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", 
			"name="+ruleName, "dir=in", "action=block", "remoteip="+ip)
	} else {
		// iptables -I INPUT -s 1.2.3.4 -j DROP
		cmd = exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to block IP in kernel", "ip", ip, "err", err, "output", string(output))
		return err
	}
	logger.Info("IP blocked at kernel level (L3)", "ip", ip)
	return nil
}

// UnblockIPKernel removes a kernel-level block for an IP address.
func UnblockIPKernel(ip string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		ruleName := fmt.Sprintf("AegisBlock_%s", ip)
		cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	} else {
		cmd = exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if runtime.GOOS == "windows" && strings.Contains(string(output), "No rules match") {
			return nil // Already deleted
		}
		logger.Error("Failed to unblock IP in kernel", "ip", ip, "err", err, "output", string(output))
		return err
	}
	logger.Info("IP unblocked at kernel level (L3)", "ip", ip)
	return nil
}

// TakeoverPort uses firewall redirection to "hijack" traffic from an occupied port.
func TakeoverPort(occupiedPort, internalPort int) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 connectport=8888 connectaddress=127.0.0.1
		cmd = exec.Command("netsh", "interface", "portproxy", "add", "v4tov4", 
			fmt.Sprintf("listenport=%d", occupiedPort), "listenaddress=0.0.0.0", 
			fmt.Sprintf("connectport=%d", internalPort), "connectaddress=127.0.0.1")
	} else {
		// iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8888
		cmd = exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", 
			"--dport", fmt.Sprintf("%d", occupiedPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", internalPort))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to hijack port via firewall", "from", occupiedPort, "to", internalPort, "err", err, "output", string(output))
		return err
	}
	logger.Info("Port Hijack Active (Hot Takeover)", "external_port", occupiedPort, "internal_proxy_port", internalPort)
	return nil
}

// ReleasePort removes the firewall redirection.
func ReleasePort(occupiedPort, internalPort int) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("netsh", "interface", "portproxy", "delete", "v4tov4", 
			fmt.Sprintf("listenport=%d", occupiedPort), "listenaddress=0.0.0.0")
	} else {
		cmd = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", 
			"--dport", fmt.Sprintf("%d", occupiedPort), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", internalPort))
	}

	cmd.Run()
	logger.Info("Port Hijack Released", "port", occupiedPort)
	return nil
}

func hardenWindows() {
	logger.Info("Applying Windows network hardening...")
	// Note: Detailed ICMP rate limiting in Windows requires specialized config, 
	// but we can ensure the firewall is ON and standard protections are active.
	cmds := [][]string{
		{"advfirewall", "set", "allprofiles", "state", "on"},
		// Disable ICMP Echo requests (pings) if needed, or leave to user.
		// For now, just ensure firewall is active.
	}

	for _, c := range cmds {
		exec.Command("netsh", c...).Run()
	}
}

func hardenLinux() {
	logger.Info("Applying Linux network hardening (iptables/sysctl)...")
	// Rate limit ICMP (ping) to 1/sec
	exec.Command("iptables", "-A", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", 
		"-m", "limit", "--limit", "1/s", "--limit-burst", "5", "-j", "ACCEPT").Run()
	exec.Command("iptables", "-A", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP").Run()

	// Anti-SYN flood
	exec.Command("sysctl", "-w", "net.ipv4.tcp_syncookies=1").Run()
	exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=1").Run()
}
