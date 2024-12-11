package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/go-jose/go-jose/v4"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/rs/zerolog/log"
)

const (
	Name = "aws"
)

type Config struct {
	Region     string
	IdentityID string
}

type Provider struct {
	region     string
	identityID string
	tokenPath  string
}

func New(region, identityID, tokenPath string) *Provider {
	return &Provider{
		region:     region,
		identityID: identityID,
		tokenPath:  tokenPath,
	}
}

func (p *Provider) GetToken(ctx context.Context) (string, error) {
	// Create a new session using the default credentials
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(p.region),
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to create AWS session")
		return "", err
	}

	// Create a Cognito Identity client
	cognitoClient := cognitoidentity.New(sess)

	// Use the service account token to get a JWT token
	serviceAccountToken, err := os.ReadFile(p.tokenPath)
	if err != nil {
		log.Error().Err(err).Msg("failed to read service account token")
		return "", err
	}

	// getting issuer from token
	issuer, err := p.getIssuer()
	if err != nil {
		log.Error().Err(err).Msg("failed to get issuer from token")
		return "", err
	}
	issuer = strings.TrimPrefix(issuer, "https://")

	tokenResp, err := cognitoClient.GetOpenIdToken(&cognitoidentity.GetOpenIdTokenInput{
		IdentityId: aws.String(p.identityID),
		Logins: map[string]*string{
			issuer: aws.String(string(serviceAccountToken)),
		},
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to get open id token")
		return "", err
	}

	return *tokenResp.Token, nil

}

func (p *Provider) GetPublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	// Construct the OpenID discovery URL
	jwksURI := fmt.Sprintf("https://cognito-identity.%s.amazonaws.com/.well-known/jwks_uri", p.region)

	// need to use another library beacuse Cognito marshals the JWKs in a way that is not compatible with go-jose (legacy base64)
	set, err := jwk.Fetch(ctx, jwksURI)
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch JWKs")
		return nil, err
	}

	jsonSet, err := json.Marshal(set)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal JWKs")
		return nil, err
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(jsonSet, &keySet); err != nil {
		log.Error().Err(err).Msg("failed to decode JWKs")
		return nil, err
	}

	return &keySet, nil
}

func (h *Provider) getIssuer() (string, error) {
	token, err := os.ReadFile(h.tokenPath)
	if err != nil {
		return "", err
	}

	// Split the token into its parts
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}

	// Decode the payload part (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	// Define a struct to hold the payload data
	var claims struct {
		Issuer string `json:"iss"`
	}

	// Unmarshal the payload into the struct
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}

	return claims.Issuer, nil
}
