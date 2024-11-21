package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"aegisproxy.io/aegis-proxy/internal/provider"
	"aegisproxy.io/aegis-proxy/internal/provider/hashicorpvault"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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
	IdentityOut          string
	IdentityIn           []string

	TokenGracePeriod time.Duration

	VaultConfig hashicorpvault.Config
}

type ProxyServer struct {
	cfg *Config

	inServer  *http.Server
	outServer *http.Server

	token   string
	jwkKeys *jose.JSONWebKeySet
}

func New(cfg *Config) (*ProxyServer, error) {
	var err error
	p := &ProxyServer{
		cfg: cfg,
	}
	p.inServer = &http.Server{Addr: fmt.Sprintf(":%s", p.cfg.InPort), Handler: http.HandlerFunc(p.ingressProxyHandler)}
	p.outServer = &http.Server{Addr: fmt.Sprintf(":%s", p.cfg.OutPort), Handler: http.HandlerFunc(p.egressProxyHandler)}

	if p.cfg.Type == IngressEgressProxy || p.cfg.Type == IngressProxy { // must read public keys
		var keys *jose.JSONWebKeySet
		switch p.cfg.IdentityProviderType {
		case hashicorpvault.Name:
			log.Trace().
				Str("vault_addr", p.cfg.VaultConfig.VaultAddr).
				Strs("identityIn", p.cfg.IdentityIn).
				Str("identityOut", p.cfg.IdentityOut).
				Msg("getting public keys from hashicorp vault")
			h := hashicorpvault.New(p.cfg.VaultConfig.VaultAddr, p.cfg.IdentityOut, "")
			p.jwkKeys, err = h.GetPublicKeys(context.Background())
			if err != nil {
				log.Error().Err(err).Msg("failed to get public keys")
				return nil, err
			}
			log.Trace().Interface("keys", keys).Msg("got public keys")

		}
	}
	return p, nil
}

func (p *ProxyServer) StartInServer() error {
	log.Info().Str("inPort", p.cfg.InPort).Msg("Starting ingress proxy server")
	return p.inServer.ListenAndServe()
}
func (p *ProxyServer) StartOutServer() error {
	log.Info().Str("outPort", p.cfg.OutPort).Msg("Starting egress proxy server")
	return p.outServer.ListenAndServe()
}

func (p *ProxyServer) Shutdown(ctx context.Context) error {
	p.inServer.Shutdown(ctx)
	p.outServer.Shutdown(ctx)
	return nil
}

func (p *ProxyServer) egressProxyHandler(w http.ResponseWriter, r *http.Request) {
	log.Trace().
		Str("type", p.cfg.Type).
		Str("uuid", p.cfg.UUID).
		Str("identity_provider_type", p.cfg.IdentityProviderType).
		Str("method", r.Method).
		Str("host", r.Host).
		Interface("url", r.URL).
		Msg("Received OUT request")
	err := p.getToken()
	if err != nil {
		http.Error(w, "failed to read token", http.StatusInternalServerError)
		return
	}
	log.Trace().Str("bearer", p.token).Str("identityOut", p.cfg.IdentityOut).Msg("got bearer")
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.token))

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

func (p *ProxyServer) ingressProxyHandler(w http.ResponseWriter, r *http.Request) {
	log.Trace().
		Str("type", p.cfg.Type).
		Str("uuid", p.cfg.UUID).
		Str("identity_provider_type", p.cfg.IdentityProviderType).
		Str("method", r.Method).
		Str("host", r.Host).
		Interface("url", r.URL).
		Msg("Received IN request")

	log.Debug().Msg("checking bearer token")
	// Extract bearer token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Error().Msg("missing Authorization header")
		http.Error(w, "missing Authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		log.Error().Msg("invalid Authorization header format")
		http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	bearerToken := parts[1]
	log.Trace().
		Str("bearerToken", bearerToken).
		Strs("identityIn", p.cfg.IdentityIn).
		Msg("received bearer token")

	// Parse and validate JWT token
	signatureAlgorithms := []jose.SignatureAlgorithm{jose.RS256} // Replace with actual supported algorithms
	token, err := jwt.ParseSigned(bearerToken, signatureAlgorithms)
	if err != nil {
		log.Error().Err(err).Msg("failed to parse JWT token")
		http.Error(w, "invalid token format", http.StatusUnauthorized)
		return
	}

	// Try to validate with jwt public key
	kid := token.Headers[0].KeyID
	if p.jwkKeys.Key(kid) == nil {
		log.Error().Str("keyID", kid).Msg("key not found")
		http.Error(w, "key not found", http.StatusUnauthorized)
		return
	}

	log.Trace().
		Str("keyID", kid).
		Interface("key", p.jwkKeys.Key(kid)).
		Msg("validating token with key")

	var claims map[string]interface{}

	key := p.jwkKeys.Key(kid)[0]
	err = token.Claims(&key, &claims)
	if err != nil {
		log.Error().Err(err).Msg("failed to validate token")
		http.Error(w, "invalid token signature", http.StatusUnauthorized)
		return
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

func (p *ProxyServer) getToken() error {
	if p.token == "" || provider.IsTokenExpired(p.token, p.cfg.TokenGracePeriod) {
		log.Trace().Msg("token is expired or empty, getting new token")
		token, err := os.ReadFile(p.cfg.TokenPath)
		if err != nil {
			log.Error().Err(err).Msg("failed to read token")
			return err
		}
		var provider provider.Provider
		switch p.cfg.IdentityProviderType {
		case hashicorpvault.Name:
			log.Trace().
				Str("vault_addr", p.cfg.VaultConfig.VaultAddr).
				Str("identity", p.cfg.IdentityOut).
				Str("token", string(token)).
				Msg("getting token from hashicorp vault")
			provider = hashicorpvault.New(p.cfg.VaultConfig.VaultAddr, p.cfg.IdentityOut, string(token))
		default:
			log.Error().Str("type", p.cfg.IdentityProviderType).Msg("provider not known")
			return fmt.Errorf("provider not known")
		}

		p.token, err = provider.GetToken(context.Background())
		if err != nil {
			log.Error().Err(err).Msg("failed to get token")
			return err
		}
	}
	return nil

}
