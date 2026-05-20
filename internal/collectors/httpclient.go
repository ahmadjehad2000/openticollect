package collectors

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// TorClient builds an HTTP client routed through a SOCKS5 proxy (e.g. Tor at
// socks5://127.0.0.1:9050). It carries the openTIcollect User-Agent and a
// generous timeout, since .onion sites are slow.
func TorClient(proxyAddr string) (*http.Client, error) {
	u, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("tor: parse proxy %q: %w", proxyAddr, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("tor: proxy %q has no host", proxyAddr)
	}
	dialer, err := proxy.SOCKS5("tcp", u.Host, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("tor: socks5 dialer: %w", err)
	}
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: uaTransport{rt: &http.Transport{Dial: dialer.Dial}},
	}, nil
}
