package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"

	"aegisproxy.io/aegis-proxy/internal/provider"
	"aegisproxy.io/aegis-proxy/internal/provider/hashicorpvault"
	"github.com/rs/zerolog/log"
)

const (
	IngressEgressProxy = "ingress-egress"
	IngressProxy       = "ingress"
	EgressProxy        = "egress"
)

type Config struct {
	InPort               string
	OutPort              string
	Type                 string
	TokenPath            string
	UUID                 string
	IdentityProviderType string
	Identity             string

	VaultConfig hashicorpvault.Config
}

type ProxyServer struct {
	cfg *Config

	inServer  *http.Server
	outServer *http.Server
}

func New(cfg *Config) *ProxyServer {
	p := &ProxyServer{
		cfg: cfg,
	}
	p.inServer = &http.Server{Addr: fmt.Sprintf(":%s", p.cfg.InPort), Handler: http.HandlerFunc(p.proxyHandler)}
	p.outServer = &http.Server{Addr: fmt.Sprintf(":%s", p.cfg.OutPort), Handler: http.HandlerFunc(p.proxyHandler)}
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
		Str("type", p.cfg.Type).
		Str("uuid", p.cfg.UUID).
		Str("identity_provider_type", p.cfg.IdentityProviderType).
		Str("method", r.Method).
		Str("host", r.Host).
		Interface("url", r.URL).
		Msg("Received request")
	if p.cfg.Type == EgressProxy {
		//read token
		token, err := os.ReadFile(p.cfg.TokenPath)
		if err != nil {
			log.Error().Err(err).Msg("failed to read token")
			http.Error(w, "failed to read token", http.StatusInternalServerError)
			return
		}
		var provider provider.Provider
		switch p.cfg.IdentityProviderType {
		case hashicorpvault.Name:
			log.Trace().
				Str("vault_addr", p.cfg.VaultConfig.VaultAddr).
				Str("identity", p.cfg.Identity).
				Str("token", string(token)).
				Msg("getting token from hashicorp vault")
			provider = hashicorpvault.New(p.cfg.VaultConfig.VaultAddr, p.cfg.Identity, string(token))
		default:
			log.Error().Str("type", p.cfg.IdentityProviderType).Msg("provider not known")
		}

		bearer, err := provider.GetToken(context.Background())
		if err != nil {
			log.Error().Err(err).Msg("failed to get token")
			http.Error(w, "failed to get token", http.StatusInternalServerError)
			return
		}
		log.Trace().Str("bearer", bearer).Msg("got bearer")
		r.Header.Set("Authentication", fmt.Sprintf("Bearer %s", bearer))
	}

	proxy := &httputil.ReverseProxy{
		Director: func(target *http.Request) {
			target.URL.Scheme = "http"
			target.URL.Host = r.Host
			target.Host = r.Host
			target.Header = r.Header
			target.Header.Set("X-Aegis-Proxy", "true")
			target.Header.Add("X-Aegis-Proxy-ID", fmt.Sprintf("%s-%s", p.cfg.Type, p.cfg.UUID))
		},
	}
	proxy.ServeHTTP(w, r)
}
