package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"aegisproxy.io/aegis-proxy/internal/provider/azure"
	"aegisproxy.io/aegis-proxy/internal/provider/hashicorpvault"
	"aegisproxy.io/aegis-proxy/internal/proxy"
	"aegisproxy.io/aegis-proxy/internal/traces"
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
var identityOut string
var identityIn []string
var tokenGracePeriod time.Duration

var policy string

// vault specific flags
var vaultAddr string

// azure specific flags
var azureTenantID string
var azureClientID string

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

	// identities
	runCmd.Flags().StringVarP(&identityOut, "identity", "n", "aegisproxy", "identity name")
	runCmd.Flags().StringSliceVar(&identityIn, "identity-allowed", []string{}, "identity allowed name")
	runCmd.Flags().StringVarP(&identityProviderType, "identity-provider", "p", hashicorpvault.Name, "identity provider type")

	// vault
	runCmd.Flags().StringVarP(&vaultAddr, "vault-address", "a", "http://127.0.0.1:8200", "vault address")

	// azure
	runCmd.Flags().StringVarP(&azureTenantID, "azure-tenant-id", "", "", "azure tenant id")
	runCmd.Flags().StringVarP(&azureClientID, "azure-client-id", "", "", "azure client id")
	// token
	runCmd.Flags().DurationVarP(&tokenGracePeriod, "token-grace-period", "g", 1*time.Minute, "token grace period")

	// policy
	runCmd.Flags().StringVarP(&policy, "policy", "l", "", "policy name")
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
		Strs("identityIn", identityIn).
		Str("identityOut", identityOut).
		Str("token_path", tokenPath).
		Str("vault_addr", vaultAddr).
		Msg("Starting proxy server")

	cfg := &proxy.Config{
		UUID:                 proxyuid,
		InPort:               inPort,
		OutPort:              outPort,
		Type:                 proxyType,
		TokenPath:            tokenPath,
		IdentityIn:           identityIn,
		IdentityOut:          identityOut,
		Policy:               policy,
		IdentityProviderType: identityProviderType,
		VaultConfig: hashicorpvault.Config{
			VaultAddr: vaultAddr,
		},
		AzureConfig: azure.Config{
			TenantID: azureTenantID,
			ClientID: azureClientID,
		},
		VersionInfo: proxy.VersionInfo{
			Version:   Version,
			GoVersion: GoVersion,
			BuildUser: BuildUser,
			BuildTime: BuildTime,
		},
	}
	p, err := proxy.New(cmd.Context(), cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create proxy server")
	}

	tracer, err := traces.New(cmd.Context())
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create tracer")
	}
	defer tracer.Shutdown(cmd.Context())

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
