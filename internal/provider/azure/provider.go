package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog/log"
)

const (
	Name = "azure"
)

type Config struct {
	TenantID string
	ClientID string
}

type Provider struct {
	TenantID  string
	ClientID  string
	TokenPath string
}

func New(tenantID, clientID, tokenPath string) *Provider {
	return &Provider{
		TenantID:  tenantID,
		ClientID:  clientID,
		TokenPath: tokenPath,
	}
}

func (p *Provider) GetToken(ctx context.Context) (string, error) {

	log.Trace().
		Str("tenant_id", p.TenantID).
		Str("client_id", p.ClientID).
		Str("token_path", p.TokenPath).
		Msg("creating workload identity credential")
	cred, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
		TenantID:      p.TenantID,
		ClientID:      p.ClientID,
		TokenFilePath: p.TokenPath,
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to create workload identity credential")
		return "", err
	}

	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{fmt.Sprintf("%s/.default", p.ClientID)},
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to get token")
		return "", err
	}

	return token.Token, nil
}

func (p *Provider) GetPublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	// Construct the OpenID discovery URL
	discoveryURL := "https://login.microsoftonline.com/" + p.TenantID + "/v2.0/.well-known/openid-configuration"

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
