package provider

import "context"

type Provider interface {
	GetToken(ctx context.Context) (string, error)
}
