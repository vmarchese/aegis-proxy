package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/rs/zerolog/log"
)

type ProxyServer struct {
	InPort    string
	OutPort   string
	Type      string
	TokenPath string

	uuid      string
	inServer  *http.Server
	outServer *http.Server
}

func New(proxyuid, inPort, outPort, proxyType string, tokenPath string) *ProxyServer {
	p := &ProxyServer{
		InPort:    inPort,
		OutPort:   outPort,
		Type:      proxyType,
		TokenPath: tokenPath,
		uuid:      proxyuid,
	}
	p.inServer = &http.Server{Addr: fmt.Sprintf(":%s", p.InPort), Handler: http.HandlerFunc(p.proxyHandler)}
	p.outServer = &http.Server{Addr: fmt.Sprintf(":%s", p.OutPort), Handler: http.HandlerFunc(p.proxyHandler)}
	return p
}

func (p *ProxyServer) StartInServer() error {
	return p.inServer.ListenAndServe()
}
func (p *ProxyServer) StartOutServer() error {
	return p.outServer.ListenAndServe()
}

func (p *ProxyServer) Shutdown(ctx context.Context) error {
	p.inServer.Shutdown(ctx)
	p.outServer.Shutdown(ctx)
	return nil
}

func (p *ProxyServer) proxyHandler(w http.ResponseWriter, r *http.Request) {
	log.Trace().
		Str("type", p.Type).
		Str("uuid", p.uuid).
		Str("method", r.Method).
		Str("host", r.Host).
		Interface("url", r.URL).
		Msg("Received request")

	proxy := &httputil.ReverseProxy{
		Director: func(target *http.Request) {
			target.URL.Scheme = "http"
			target.URL.Host = r.Host
			target.Host = r.Host
			target.Header = r.Header
			target.Header.Set("X-Aegis-Proxy", "true")
			target.Header.Add("X-Aegis-Proxy-ID", fmt.Sprintf("%s-%s", p.Type, p.uuid))
		},
	}
	proxy.ServeHTTP(w, r)
}
