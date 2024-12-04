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
	"aegisproxy.io/aegis-proxy/internal/provider/azure"
	"aegisproxy.io/aegis-proxy/internal/provider/hashicorpvault"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/rs/zerolog/log"
	aegisv1 "github.com/vmarchese/aegis-operator/api/v1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const (
	IngressEgressProxy = "ingress-egress"
	IngressProxy       = "ingress"
	EgressProxy        = "egress"
)

var (
	tracer = otel.GetTracerProvider().Tracer("aegisproxy")
)

type VersionInfo struct {
	Version   string
	GoVersion string
	BuildUser string
	BuildTime string
}

type Config struct {
	InPort               string
	OutPort              string
	Type                 string
	TokenPath            string
	UUID                 string
	IdentityProviderType string
	IdentityOut          string
	IdentityIn           []string
	Policy               string
	VersionInfo          VersionInfo
	TokenGracePeriod     time.Duration

	VaultConfig hashicorpvault.Config
	AzureConfig azure.Config
}

type ProxyServer struct {
	cfg *Config

	inServer  *http.Server
	outServer *http.Server

	token   string
	jwkKeys *jose.JSONWebKeySet

	ingressPolicy *aegisv1.IngressPolicy
	dynamicClient *dynamic.DynamicClient
	watcher       watch.Interface
	namespace     string
}

func New(ctx context.Context, cfg *Config) (*ProxyServer, error) {
	var err error
	p := &ProxyServer{
		cfg: cfg,
	}
	p.inServer = &http.Server{Addr: fmt.Sprintf(":%s", p.cfg.InPort), Handler: http.HandlerFunc(p.ingressProxyHandler)}
	p.outServer = &http.Server{Addr: fmt.Sprintf(":%s", p.cfg.OutPort), Handler: http.HandlerFunc(p.egressProxyHandler)}

	if p.cfg.Type == IngressEgressProxy || p.cfg.Type == IngressProxy { // must read public keys
		var provider provider.Provider
		switch p.cfg.IdentityProviderType {
		case hashicorpvault.Name:
			log.Trace().
				Str("vault_addr", p.cfg.VaultConfig.VaultAddr).
				Strs("identityIn", p.cfg.IdentityIn).
				Str("identityOut", p.cfg.IdentityOut).
				Msg("getting public keys from hashicorp vault")
			provider = hashicorpvault.New(p.cfg.VaultConfig.VaultAddr, p.cfg.IdentityOut, "")

		case azure.Name:
			log.Trace().
				Str("tenant_id", p.cfg.AzureConfig.TenantID).
				Strs("identityIn", p.cfg.IdentityIn).
				Str("identityOut", p.cfg.IdentityOut).
				Str("token_path", p.cfg.TokenPath).
				Str("client_id", p.cfg.AzureConfig.ClientID).
				Msg("getting public keys from azure")
			provider = azure.New(p.cfg.AzureConfig.TenantID, p.cfg.AzureConfig.ClientID, p.cfg.TokenPath)
		}

		p.jwkKeys, err = provider.GetPublicKeys(context.Background())
		if err != nil {
			log.Error().Err(err).Msg("failed to get public keys")
			return nil, err
		}
		log.Trace().Interface("keys", p.jwkKeys).Msg("got public keys")

		if strings.TrimSpace(p.cfg.Policy) != "" {

			namespacePath := "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
			namespace, err := os.ReadFile(namespacePath)
			if err != nil {
				return nil, err
			}
			p.namespace = string(namespace)

			config, err := rest.InClusterConfig()
			if err != nil {
				return nil, err
			}
			dynamicClient, err := dynamic.NewForConfig(config)
			if err != nil {
				return nil, err
			}
			p.dynamicClient = dynamicClient

			err = p.getIngressPolicy(ctx)
			if err != nil {
				return nil, err
			}

			watcher, err := p.dynamicClient.Resource(schema.GroupVersionResource{
				Group:    "aegis.aegisproxy.io",
				Version:  "v1",
				Resource: "ingresspolicies",
			}).Namespace(p.namespace).Watch(ctx, v1.ListOptions{
				FieldSelector: "metadata.name=" + p.ingressPolicy.Name,
			})
			if err != nil {
				return nil, err
			}
			p.watcher = watcher

			go p.startWatcher(ctx)

			log.Trace().Interface("ingressPolicy", p.ingressPolicy).Msg("ingress policy found")

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
	p.watcher.Stop()
	return nil
}

func (p *ProxyServer) egressProxyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := tracer.Start(ctx, fmt.Sprintf("%s-egress", p.cfg.IdentityOut),
		trace.WithSpanKind(trace.SpanKindServer),
	)
	defer span.End()
	r = r.WithContext(ctx)

	span.SetAttributes(attribute.String("aegis.proxy.identity", p.cfg.IdentityOut),
		attribute.String("aegis.proxy.type", p.cfg.Type),
		attribute.String("aegis.proxy.uuid", p.cfg.UUID),
		attribute.String("aegis.proxy.namespace", p.namespace),
	)

	log.Trace().
		Str("type", p.cfg.Type).
		Str("uuid", p.cfg.UUID).
		Str("identity_provider_type", p.cfg.IdentityProviderType).
		Str("method", r.Method).
		Str("host", r.Host).
		Interface("headers", r.Header).
		Interface("url", r.URL).
		Msg("Received OUT request")
	err := p.getToken()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		http.Error(w, "failed to read token", http.StatusInternalServerError)
		return
	}
	log.Trace().Str("bearer", p.token).Str("identityOut", p.cfg.IdentityOut).Msg("got bearer")
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.token))

	proxy := &httputil.ReverseProxy{
		Director: func(target *http.Request) {
			otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(target.Header))
			target = target.WithContext(r.Context())
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

	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := tracer.Start(ctx, "ingress", trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()
	r = r.WithContext(ctx)
	span.SetAttributes(
		attribute.String("aegis.proxy.type", p.cfg.Type),
		attribute.String("aegis.proxy.uuid", p.cfg.UUID),
		attribute.String("aegis.proxy.namespace", p.namespace),
	)
	log.Trace().
		Str("type", p.cfg.Type).
		Str("uuid", p.cfg.UUID).
		Str("identity_provider_type", p.cfg.IdentityProviderType).
		Str("method", r.Method).
		Str("host", r.Host).
		Interface("headers", r.Header).
		Msg("Received IN request")
	log.Debug().Msg("checking bearer token")
	// Extract bearer token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Error().Msg("missing Authorization header")
		http.Error(w, "missing Authorization header", http.StatusUnauthorized)
		span.SetStatus(codes.Error, "missing Authorization header")
		span.RecordError(fmt.Errorf("missing Authorization header"))
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		log.Error().Msg("invalid Authorization header format")
		http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)
		span.SetStatus(codes.Error, "invalid Authorization header format")
		span.RecordError(fmt.Errorf("invalid Authorization header format"))
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
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		return
	}

	// Try to validate with jwt public key
	kid := token.Headers[0].KeyID
	if p.jwkKeys.Key(kid) == nil {
		log.Error().Str("keyID", kid).Msg("key not found")
		http.Error(w, "key not found", http.StatusUnauthorized)
		span.SetStatus(codes.Error, "key not found")
		span.RecordError(fmt.Errorf("key not found"))
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
		span.RecordError(err)
		return
	}
	span.SetAttributes(
		attribute.String("aegis.proxy.in.subject", fmt.Sprintf("%v", claims["sub"])),
		attribute.String("aegis.proxy.in.name", fmt.Sprintf("%v", claims["name"])),
	)

	if p.ingressPolicy != nil {
		log.Trace().Interface("policy", p.ingressPolicy).Msg("policy to be checked")
		if err := p.validate(r, claims); err != nil {
			log.Error().Err(err).Str("policy", p.ingressPolicy.Name).Msg("policy blocked access")
			http.Error(w, fmt.Sprintf("access blocked by ingress policy: %s", err.Error()), http.StatusUnauthorized)
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)
			return
		}

	}

	proxy := &httputil.ReverseProxy{
		Director: func(target *http.Request) {
			otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(target.Header))
			target = target.WithContext(r.Context())
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

func (p *ProxyServer) validate(r *http.Request, claims map[string]interface{}) error {
	// get Path

	subject, ok := p.getSubject(claims)
	if !ok {
		return fmt.Errorf("subject not found")
	}
	for _, rule := range p.ingressPolicy.Spec.Rules {
		log.Trace().Str("rule", rule.Name).Msg("checking rule")
		if sliceContains(rule.Identities, subject) {
			log.Trace().Str("rule", rule.Name).Str("subject", subject).Msg("rule applies to identity")
			for _, path := range rule.Paths {
				if strings.HasPrefix(r.URL.Path, path) {
					log.Trace().Str("rule", rule.Name).Str("path", path).Msg("rule applies to path")
					if !sliceContains(rule.Methods, r.Method) {
						log.Trace().Str("rule", rule.Name).Str("method", r.Method).Msg("method not allowed")
						return fmt.Errorf("method %s not allowed for prefix %s by rule[%s]", r.Method, path, rule.Name)
					}
				}
			}
		}
	}
	return nil
}

func (p *ProxyServer) getSubject(claims map[string]interface{}) (string, bool) {

	switch p.cfg.IdentityProviderType {
	case hashicorpvault.Name:
		return claims["name"].(string), true
	case azure.Name:
		roles := claims["roles"].([]interface{})
		if len(roles) > 0 {
			return roles[0].(string), true
		}
		return "", false
	}
	return "", false
}

func sliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (p *ProxyServer) getToken() error {
	if p.token == "" || provider.IsTokenExpired(p.token, p.cfg.TokenGracePeriod) {
		var err error
		log.Trace().Msg("token is expired or empty, getting new token")
		var provider provider.Provider
		switch p.cfg.IdentityProviderType {
		case hashicorpvault.Name:
			token, err := os.ReadFile(p.cfg.TokenPath)
			if err != nil {
				log.Error().Err(err).Msg("failed to read token")
				return err
			}
			log.Trace().
				Str("vault_addr", p.cfg.VaultConfig.VaultAddr).
				Str("identity", p.cfg.IdentityOut).
				Str("token", string(token)).
				Msg("getting token from hashicorp vault")
			provider = hashicorpvault.New(p.cfg.VaultConfig.VaultAddr, p.cfg.IdentityOut, string(token))
		case azure.Name:
			log.Trace().
				Str("tenant_id", p.cfg.AzureConfig.TenantID).
				Str("client_id", p.cfg.AzureConfig.ClientID).
				Str("tokenpath", p.cfg.TokenPath).
				Msg("getting token from azure")
			provider = azure.New(p.cfg.AzureConfig.TenantID, p.cfg.AzureConfig.ClientID, p.cfg.TokenPath)
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

func (p *ProxyServer) getIngressPolicy(ctx context.Context) error {

	ingressPolicies, err := p.dynamicClient.Resource(schema.GroupVersionResource{
		Group:    "aegis.aegisproxy.io",
		Version:  "v1",
		Resource: "ingresspolicies",
	}).Namespace(p.namespace).
		List(ctx, v1.ListOptions{
			FieldSelector: "metadata.name=" + p.cfg.Policy,
		})
	if err != nil {
		return err
	}

	ip := &aegisv1.IngressPolicy{}
	for _, ingressPolicy := range ingressPolicies.Items {
		if ingressPolicy.GetName() == p.cfg.Policy {
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(ingressPolicy.UnstructuredContent(), ip)
			if err != nil {
				log.Error().Err(err).Msg("failed to convert ingress policy")
				continue
			}
			break
		}
	}
	p.ingressPolicy = ip
	return nil
}

func (p *ProxyServer) startWatcher(ctx context.Context) {

	for event := range p.watcher.ResultChan() {
		switch event.Type {
		case watch.Added:
			log.Trace().Msg("IngressPolicy added")
			p.getIngressPolicy(ctx)
		case watch.Modified:
			log.Trace().Msg("IngressPolicy modified")
			p.getIngressPolicy(ctx)
		case watch.Deleted:
			log.Trace().Msg("IngressPolicy deleted")
			p.ingressPolicy = nil
		default:
			log.Error().Str("type", string(event.Type)).Msg("unknown event type")
		}
	}

}
