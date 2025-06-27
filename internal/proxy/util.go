package proxy

import (
	"net/http"
	"strconv"
	"time"

	"aegisproxy.io/aegis-proxy/internal/metrics"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func HTTPError(w http.ResponseWriter, code int, err error, span trace.Span) {
	http.Error(w, err.Error(), code)
	span.SetStatus(codes.Error, err.Error())
	span.RecordError(err)
}

// responseWriter wrapper to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = 200
	}
	return rw.ResponseWriter.Write(b)
}

// recordMetrics records request metrics
func recordMetrics(proxyType, method string, startTime time.Time, statusCode int, metricsProvider *metrics.Provider) {
	if metricsProvider == nil {
		return
	}
	
	duration := time.Since(startTime).Seconds()
	metrics := metricsProvider.GetMetrics()
	
	// Record request count
	metrics.RequestsTotal.WithLabelValues(proxyType, method, strconv.Itoa(statusCode)).Inc()
	
	// Record request duration
	metrics.RequestDuration.WithLabelValues(proxyType, method).Observe(duration)
}

func recordAuthFailure(proxyType, reason string, metricsProvider *metrics.Provider) {
	if metricsProvider == nil {
		return
	}
	
	metrics := metricsProvider.GetMetrics()
	metrics.AuthFailures.WithLabelValues(proxyType, reason).Inc()
}

func recordPolicyFailure(proxyType, policyName string, metricsProvider *metrics.Provider) {
	if metricsProvider == nil {
		return
	}
	
	metrics := metricsProvider.GetMetrics()
	metrics.PolicyFailures.WithLabelValues(proxyType, policyName).Inc()
}

func updateActiveConnections(proxyType string, delta float64, metricsProvider *metrics.Provider) {
	if metricsProvider == nil {
		return
	}
	
	metrics := metricsProvider.GetMetrics()
	metrics.ActiveConnections.WithLabelValues(proxyType).Add(delta)
}
