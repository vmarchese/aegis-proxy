package metrics

import (
	"context"
	"fmt"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"net/http"
)

type ContextKey string

const SuppressInstrumentation ContextKey = "metrics.suppress"

type Option interface{}

type ExporterType string

const (
	PrometheusExporterType ExporterType = "prometheus"
	DebugExporterType      ExporterType = "debug"

	DefaultExporterType ExporterType = "prometheus"

	EnvMetricsExporter string = "OTEL_METRICS_EXPORTER"
)

type Provider struct {
	registry *prometheus.Registry
	handler  http.Handler
	Metrics  *ProxyMetrics
}

type ProxyMetrics struct {
	RequestsTotal     *prometheus.CounterVec
	RequestDuration   *prometheus.HistogramVec
	AuthFailures      *prometheus.CounterVec
	PolicyFailures    *prometheus.CounterVec
	ActiveConnections *prometheus.GaugeVec
}

func New(ctx context.Context, options ...Option) (*Provider, error) {
	exporterType := DefaultExporterType

	if os.Getenv(EnvMetricsExporter) != "" {
		exporterType = ExporterType(os.Getenv(EnvMetricsExporter))
	}

	registry := prometheus.NewRegistry()
	
	// Create proxy-specific metrics
	metrics := &ProxyMetrics{
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_proxy_requests_total",
				Help: "Total number of HTTP requests processed by the proxy",
			},
			[]string{"proxy_type", "method", "status_code"},
		),
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "aegis_proxy_request_duration_seconds",
				Help:    "Duration of HTTP requests processed by the proxy",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"proxy_type", "method"},
		),
		AuthFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_proxy_auth_failures_total",
				Help: "Total number of authentication failures",
			},
			[]string{"proxy_type", "reason"},
		),
		PolicyFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "aegis_proxy_policy_failures_total",
				Help: "Total number of policy validation failures",
			},
			[]string{"proxy_type", "policy_name"},
		),
		ActiveConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "aegis_proxy_active_connections",
				Help: "Number of active connections to the proxy",
			},
			[]string{"proxy_type"},
		),
	}

	// Register metrics with the registry
	registry.MustRegister(
		metrics.RequestsTotal,
		metrics.RequestDuration,
		metrics.AuthFailures,
		metrics.PolicyFailures,
		metrics.ActiveConnections,
	)

	var handler http.Handler
	switch exporterType {
	case PrometheusExporterType:
		handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		})
	case DebugExporterType:
		// Simple debug handler that logs metrics
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug().Msg("Metrics endpoint accessed")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("# Metrics debug mode\n"))
		})
	default:
		return nil, fmt.Errorf("invalid metrics exporter type: %s", exporterType)
	}

	return &Provider{
		registry: registry,
		handler:  handler,
		Metrics:  metrics,
	}, nil
}

func (p *Provider) GetMetricsHandler() http.Handler {
	return p.handler
}

func (p *Provider) GetMetrics() *ProxyMetrics {
	return p.Metrics
}

func (p *Provider) Shutdown(ctx context.Context) error {
	return nil
}