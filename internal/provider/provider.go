package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type Provider interface {
	GetToken(ctx context.Context) (string, error)
	GetPublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error)
}

func IsTokenExpired(token string, gracePeriod time.Duration) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return true
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return true

	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return true
	}

	return time.Now().Unix() > claims.Exp-int64(gracePeriod.Seconds())

}
