package proxy

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"aegisedge/logger"
)

type ReverseProxy struct {
	Proxy *httputil.ReverseProxy
}

func NewReverseProxy(target string) (*ReverseProxy, error) {
	url, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(url)
	
	// Professional config: Aggressive timeouts
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
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
