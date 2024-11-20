package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"aegisproxy.io/aegis-proxy/internal/provider/hashicorpvault"
	"aegisproxy.io/aegis-proxy/internal/proxy"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var inPort string
var outPort string
var proxyType string
var tokenPath string
var proxyuid string

var identityProviderType string
var identityName string
var tokenGracePeriod time.Duration

// vault specific flags
var vaultAddr string

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "run the proxy server",
	Run:   runProxy,
}

func init() {
	runCmd.Flags().StringVarP(&inPort, "inport", "i", "3127", "port to run the in proxy server on")
	runCmd.Flags().StringVarP(&outPort, "outport", "o", "3128", "port to run the out proxy server on")
	runCmd.Flags().StringVarP(&proxyType, "type", "t", "ingress", "type of proxy server to run")
	runCmd.Flags().StringVarP(&tokenPath, "token", "k", "/var/run/secrets/tokens/token", "path to the token file")
	runCmd.Flags().StringVarP(&proxyuid, "uuid", "u", uuid.New().String(), "uuid")
	runCmd.Flags().StringVarP(&identityName, "identity", "n", "aegisproxy", "identity name")

	runCmd.Flags().StringVarP(&identityProviderType, "identity-provider", "p", hashicorpvault.Name, "identity provider type")

	runCmd.Flags().StringVarP(&vaultAddr, "vault-address", "a", "http://127.0.0.1:8200", "vault address")
	runCmd.Flags().DurationVarP(&tokenGracePeriod, "token-grace-period", "g", 1*time.Minute, "token grace period")

}

func runProxy(cmd *cobra.Command, args []string) {

	if proxyuid == "" {
		proxyuid = uuid.New().String()
	}
	var wg sync.WaitGroup

	switch proxyType {
	case proxy.IngressProxy:
		wg.Add(1)
	case proxy.EgressProxy:
		wg.Add(1)
	case proxy.IngressEgressProxy:
		wg.Add(2)
	default:
		log.Fatal().Msgf("invalid proxy type: %s", proxyType)
	}

	log.Debug().
		Str("inPort", inPort).
		Str("outPort", outPort).
		Str("proxyType", proxyType).
		Str("identity_provider_type", identityProviderType).
		Str("identity", identityName).
		Str("token_path", tokenPath).
		Str("vault_addr", vaultAddr).
		Msg("Starting proxy server")

	cfg := &proxy.Config{
		UUID:                 proxyuid,
		InPort:               inPort,
		OutPort:              outPort,
		Type:                 proxyType,
		TokenPath:            tokenPath,
		Identity:             identityName,
		IdentityProviderType: identityProviderType,
		TokenGracePeriod:     tokenGracePeriod,
		VaultConfig: hashicorpvault.Config{
			VaultAddr: vaultAddr,
		},
	}
	p := proxy.New(cfg)

	switch proxyType {
	case proxy.IngressProxy:
		log.Info().Str("inPort", inPort).Msg("Starting ingress proxy server")
		go func() {
			defer wg.Done()
			p.StartInServer()
		}()
	case proxy.EgressProxy:
		log.Info().Str("outPort", outPort).Msg("Starting egress proxy server")
		go func() {
			defer wg.Done()
			p.StartOutServer()
		}()
	case proxy.IngressEgressProxy:
		log.Info().Str("inPort", inPort).Str("outPort", outPort).Msg("Starting ingress-egress proxy server")
		go func() {
			defer wg.Done()
			p.StartInServer()
		}()
		go func() {
			defer wg.Done()
			p.StartOutServer()
		}()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	p.Shutdown(context.Background())
	wg.Wait()

}
