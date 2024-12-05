package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog/log"
)

const (
	Name = "kubernetes"
)

type Config struct {
	Issuer string
}

type Provider struct {
	issuer    string
	tokenPath string
}

func New(issuer, tokenPath string) *Provider {
	return &Provider{
		issuer:    issuer,
		tokenPath: tokenPath,
	}
}

func (p *Provider) GetToken(ctx context.Context) (string, error) {
	token, err := os.ReadFile(p.tokenPath)
	if err != nil {
		log.Error().Err(err).Msg("failed to read token")
		return "", err
	}
	return string(token), nil

}

func (p *Provider) GetPublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	// Construct the OpenID discovery URL
	discoveryURL := p.issuer + "/.well-known/openid-configuration"

	// Fetch the OpenID configuration
	resp, err := http.Get(discoveryURL)
	if err != nil {
		log.Error().Err(err).Msg("failed to get OpenID configuration")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Error().Msgf("failed to get OpenID configuration: %s", resp.Status)
		return nil, fmt.Errorf("failed to get OpenID configuration: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("failed to read OpenID configuration")
		return nil, err
	}

	log.Trace().Str("body", string(body)).Msg("OpenID configuration")

	var config struct {
		JWKSURI string `json:"jwks_uri"`
	}

	if err := json.Unmarshal(body, &config); err != nil {
		log.Error().Err(err).Msg("failed to decode OpenID configuration")
		return nil, err
	}

	// Fetch the JWKs from the JWKS URI
	log.Trace().Str("uri", config.JWKSURI).Msg("fetching JWKs")
	jwksResp, err := http.Get(config.JWKSURI)
	if err != nil {
		log.Error().Err(err).Msg("failed to get JWKs")
		return nil, err
	}
	defer jwksResp.Body.Close()

	jwksBody, err := io.ReadAll(jwksResp.Body)
	if err != nil {
		log.Error().Err(err).Msg("failed to read JWKs")
		return nil, err
	}

	log.Trace().Str("body", string(jwksBody)).Msg("JWKs")

	if jwksResp.StatusCode != http.StatusOK {
		log.Error().Msgf("failed to get JWKs: %s", jwksResp.Status)
		return nil, fmt.Errorf("failed to get JWKs: %s", jwksResp.Status)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(jwksBody, &keySet); err != nil {
		log.Error().Err(err).Msg("failed to decode JWKs")
		return nil, err
	}

	return &keySet, nil
}
