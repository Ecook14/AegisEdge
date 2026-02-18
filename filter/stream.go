package filter

import (
	"io"
	"net"
	"time"

	"aegisedge/logger"
)

// StreamProxy provides L4 protection (connection limiting) for non-HTTP protocols.
func StreamProxy(ln net.Listener, targetAddr string, l4 *L4Filter) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			logger.Error("Stream proxy accept error", "err", err)
			return
		}

		go func(conn net.Conn) {
			defer conn.Close()

			if !l4.AllowConnection(conn.RemoteAddr().String()) {
				return
			}
			defer l4.ReleaseConnection(conn.RemoteAddr().String())

			targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
			if err != nil {
				logger.Error("Stream proxy dial error", "addr", targetAddr, "err", err)
				return
			}
			defer targetConn.Close()

			// Bidirectional copy
			done := make(chan bool, 2)
			go func() {
				io.Copy(targetConn, conn)
				done <- true
			}()
			go func() {
				io.Copy(conn, targetConn)
				done <- true
			}()
			<-done
		}(clientConn)
	}
}
