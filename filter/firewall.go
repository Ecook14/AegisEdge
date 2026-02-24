// This file is intentionally empty.
// Kernel-level firewall blocking is implemented in orchestration_firewall.go via BlockIPKernel.
// Use BlockIPKernel(ip) for iptables/netsh integration (supports both Linux and Windows).
// BlockIP (Linux-only) has been consolidated into BlockIPKernel for cross-platform support.
package filter
