package hashicorpvault

import (
	"context"
	"encoding/json"

	"github.com/go-jose/go-jose/v4"
	vault_client "github.com/hashicorp/vault-client-go"
	vault_client_schema "github.com/hashicorp/vault-client-go/schema"
	"github.com/rs/zerolog/log"
)

const (
	Name = "hashicorp.vault"
)

type Config struct {
	VaultAddr string
}

type Provider struct {
	VaultAddr string
	Role      string
	JWT       string
}

func New(vaultAddr, role, jwt string) *Provider {
	return &Provider{
		VaultAddr: vaultAddr,
		Role:      role,
		JWT:       jwt,
	}
}

func (p *Provider) GetToken(ctx context.Context) (string, error) {
	// Create a new Vault client
	client, err := vault_client.New(vault_client.WithAddress(p.VaultAddr))
	if err != nil {
		return "", err
	}

	authInfo, err := client.Auth.JwtLogin(ctx, vault_client_schema.JwtLoginRequest{
		Jwt:  p.JWT,
		Role: p.Role,
	})
	if err != nil {
		log.Error().Err(err).Msg("unable to log in with JWT auth")
		return "", err
	}

	vaultToken := authInfo.Auth.ClientToken
	if err := client.SetToken(vaultToken); err != nil {
		log.Error().Err(err).Msg("unable to set token")
		return "", err
	}

	// Retrieve the issued JWT OIDC token
	oidcInfo, err := client.Identity.OidcGenerateToken(ctx, p.Role)
	if err != nil {
		log.Error().Err(err).Msg("unable to get jwt token")
		return "", err
	}
	token := oidcInfo.Data["token"].(string)

	return token, nil
}

func (p *Provider) GetPublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	client, err := vault_client.New(vault_client.WithAddress(p.VaultAddr))
	if err != nil {
		log.Error().Err(err).Msg("failed to create vault client")
		return nil, err
	}
	keys, err := client.Identity.OidcReadPublicKeys(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to read public keys")
		return nil, err
	}
	k := keys.Data
	jwkeys, err := json.Marshal(k)
	if err != nil {
		panic(err)
	}

	jwks := &jose.JSONWebKeySet{}
	err = json.Unmarshal(jwkeys, jwks)
	if err != nil {
		return nil, err
	}
	return jwks, nil
}
