package filter

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"syscall"
	"time"

	"aegisedge/logger"
)

// StreamProxy provides L4 protection for non-HTTP protocols.
// It supports PROXY Protocol v1 so that the real client IP is used
// for connection limiting when behind a TCP load balancer (HAProxy, AWS NLB).
func StreamProxy(ln net.Listener, targetAddr string, l4 *L4Filter) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			logger.Error("Stream proxy accept error", "err", err)
			return
		}

		go handleStream(clientConn, targetAddr, l4)
	}
}

func handleStream(conn net.Conn, targetAddr string, l4 *L4Filter) {
	defer conn.Close()

	// Peek at the first line to detect a PROXY Protocol v1 header.
	// Use a buffered reader so bytes consumed for detection can be replayed.
	br := bufio.NewReader(conn)
	realAddr, reader := resolveProxyProtocol(br, conn)

	if !l4.AllowConnection(realAddr) {
		logger.Warn("L4 stream connection rejected", "addr", realAddr)
		return
	}
	defer l4.ReleaseConnection(realAddr)

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Mark packets on Linux/WSL only (SO_MARK = 36)
				if runtime.GOOS == "linux" {
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 36, 0xAE615)
				}
			})
		},
	}

	targetConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		logger.Error("Stream proxy dial error", "addr", targetAddr, "err", err)
		return
	}
	defer targetConn.Close()

	// Bidirectional copy — reader may have buffered bytes consumed during peeking.
	done := make(chan bool, 2)
	go func() {
		io.Copy(targetConn, reader)
		done <- true
	}()
	go func() {
		io.Copy(conn, targetConn)
		done <- true
	}()
	<-done
}

// resolveProxyProtocol peeks at the connection for a PROXY Protocol v1 header.
// Format: "PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n"
// Returns the resolved address string and an io.Reader that replays all bytes.
func resolveProxyProtocol(br *bufio.Reader, conn net.Conn) (string, io.Reader) {
	fallback := conn.RemoteAddr().String()

	// Peek enough bytes to read the first line without blocking indefinitely.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{}) // clear deadline after peek

	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "PROXY ") {
		// Not a PROXY protocol header; replay the peeked bytes.
		return fallback, io.MultiReader(strings.NewReader(line), br)
	}

	// Parse: PROXY TCP4 203.0.113.5 10.0.0.1 1234 22
	parts := strings.Fields(line)
	if len(parts) < 6 || (parts[1] != "TCP4" && parts[1] != "TCP6") {
		return fallback, br
	}

	srcIP := parts[2]
	srcPort := parts[4]
	realAddr := fmt.Sprintf("%s:%s", srcIP, srcPort)

	logger.Info("PROXY Protocol: resolved real client IP", "real_addr", realAddr, "proxy_addr", conn.RemoteAddr())
	return realAddr, br
}
