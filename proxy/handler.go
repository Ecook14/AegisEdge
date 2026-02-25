package proxy

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime"
	"sync"
	"syscall"
	"time"

	"aegisedge/logger"
)

// proxyBufferPool recycles 32KB buffers used by httputil.ReverseProxy.
// This eliminates ~10,000 allocations per second at high RPS.
type proxyBufferPool struct {
	pool sync.Pool
}

func (p *proxyBufferPool) Get() []byte {
	if v := p.pool.Get(); v != nil {
		return v.([]byte)
	}
	return make([]byte, 32*1024)
}

func (p *proxyBufferPool) Put(buf []byte) {
	p.pool.Put(buf)
}

var sharedBufferPool = &proxyBufferPool{}

type ReverseProxy struct {
	Proxy *httputil.ReverseProxy
}

func NewReverseProxy(target string) (*ReverseProxy, error) {
	url, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.BufferPool = sharedBufferPool
	
	// Professional config: Aggressive timeouts
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
			Control: func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					// Mark packets on Linux/WSL only (SO_MARK = 36)
					if runtime.GOOS == "linux" {
						syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 36, 0xAE615)
					}
				})
			},
		}).DialContext,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   500,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		WriteBufferSize:       32 * 1024,
		ReadBufferSize:        32 * 1024,
	}

	// Custom error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("Proxy error", "err", err, "path", r.URL.Path)
		w.WriteHeader(http.StatusBadGateway)
	}

	return &ReverseProxy{Proxy: proxy}, nil
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.Proxy.ServeHTTP(w, r)
}
