package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"aegisproxy.io/aegis-proxy/internal/proxy"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	IngressEgressProxy = "ingress-egress"
	IngressProxy       = "ingress"
	EgressProxy        = "egress"
)

var inPort string
var outPort string
var proxyType string
var tokenPath string
var proxyuid string

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

}

func runProxy(cmd *cobra.Command, args []string) {

	if proxyuid == "" {
		proxyuid = uuid.New().String()
	}
	var wg sync.WaitGroup

	switch proxyType {
	case IngressProxy:
		wg.Add(1)
	case EgressProxy:
		wg.Add(1)
	case IngressEgressProxy:
		wg.Add(2)
	default:
		log.Fatal().Msgf("invalid proxy type: %s", proxyType)
	}

	log.Debug().
		Str("inPort", inPort).
		Str("outPort", outPort).
		Str("proxyType", proxyType).
		Msg("Starting proxy server")
	p := proxy.New(proxyuid, inPort, outPort, proxyType, tokenPath)

	switch proxyType {
	case IngressProxy:
		log.Info().Str("inPort", inPort).Msg("Starting ingress proxy server")
		go func() {
			defer wg.Done()
			p.StartInServer()
		}()
	case EgressProxy:
		log.Info().Str("outPort", outPort).Msg("Starting egress proxy server")
		go func() {
			defer wg.Done()
			p.StartOutServer()
		}()
	case IngressEgressProxy:
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
