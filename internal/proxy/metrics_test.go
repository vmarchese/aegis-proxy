package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aegisproxy.io/aegis-proxy/internal/provider/kubernetes"
	"github.com/google/uuid" // For proxy UUID
)

func TestIngressMetricsIncrementAndKeyNotFound(t *testing.T) {
	// Reset metrics that might have been affected by other tests
	http_requests_total.Reset()
	aegisproxy_token_validation_errors_total.Reset()
	http_request_duration_seconds.Reset() // Though not directly checked, good practice

	cfg := &Config{
		InPort:               "8080",
		MetricsPort:          "9091",
		Type:                 IngressProxy,
		UUID:                 uuid.NewString(),
		IdentityIn:           []string{"test-identity"},
		TokenPath:            "/dev/null",
		IdentityProviderType: "kubernetes",
		KubernetesConfig: kubernetes.Config{Issuer: "http://fake.issuer.svc"},
	}

	proxyServer, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}

	go func() {
		if err := proxyServer.StartMetricsServer(); err != nil && err != http.ErrServerClosed {
			if t != nil {
				t.Logf("Metrics server error in goroutine: %v", err)
			}
		}
	}()
	defer proxyServer.Shutdown(context.Background())
	time.Sleep(100 * time.Millisecond)

	dummyToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3RrZXkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.dummySignature"
	req := httptest.NewRequest("GET", "http://example.com/testpath", nil)
	req.Header.Set("Authorization", "Bearer "+dummyToken)

	rr := httptest.NewRecorder()
	proxyServer.ingressProxyHandler(rr, req)

	metricsResp, err := http.Get(fmt.Sprintf("http://localhost:%s/metrics", cfg.MetricsPort))
	if err != nil {
		t.Fatalf("Failed to fetch metrics: %v", err)
	}
	defer metricsResp.Body.Close()
	body, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("Failed to read metrics response body: %v", err)
	}

	expectedRequestTotalMetric := `http_requests_total{code="401",method="GET",proxy_type="ingress"} 1`
	if !strings.Contains(string(body), expectedRequestTotalMetric) {
		t.Errorf("Metrics output does not contain expected metric for http_requests_total (key not found path).\nExpected to contain: %s\nGot: %s", expectedRequestTotalMetric, string(body))
	}

	expectedTokenErrorMetric := `aegisproxy_token_validation_errors_total{proxy_type="ingress",reason="key_not_found"} 1`
	if !strings.Contains(string(body), expectedTokenErrorMetric) {
		t.Errorf("Metrics output does not contain expected metric for token validation error (key_not_found).\nExpected to contain: %s\nGot: %s", expectedTokenErrorMetric, string(body))
	}
}

func TestIngressMetricsMissingAuthHeader(t *testing.T) {
	// Reset metrics that might have been affected by other tests
	http_requests_total.Reset()
	aegisproxy_token_validation_errors_total.Reset()
	http_request_duration_seconds.Reset() // Though not directly checked, good practice

	cfg := &Config{
		MetricsPort:          "9092",
		Type:                 IngressProxy,
		UUID:                 uuid.NewString(),
		TokenPath:            "/dev/null",
		IdentityProviderType: "kubernetes",
		KubernetesConfig:     kubernetes.Config{Issuer: "http://fake.issuer.svc"},
	}

	proxyServer, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}

	go func() {
		if err := proxyServer.StartMetricsServer(); err != nil && err != http.ErrServerClosed {
			if t != nil {
				t.Logf("Metrics server error in goroutine: %v", err)
			}
		}
	}()
	defer proxyServer.Shutdown(context.Background())
	time.Sleep(100 * time.Millisecond)

	req := httptest.NewRequest("GET", "http://example.com/testpath", nil)
	rr := httptest.NewRecorder()
	proxyServer.ingressProxyHandler(rr, req)

	metricsResp, err := http.Get(fmt.Sprintf("http://localhost:%s/metrics", cfg.MetricsPort))
	if err != nil {
		t.Fatalf("Failed to fetch metrics: %v", err)
	}
	defer metricsResp.Body.Close()
	body, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("Failed to read metrics response body: %v", err)
	}

	expectedMetric := `http_requests_total{code="401",method="GET",proxy_type="ingress"} 1`
	if !strings.Contains(string(body), expectedMetric) {
		t.Errorf("Metrics output does not contain expected metric for missing auth header.\nExpected to contain: %s\nGot: %s", expectedMetric, string(body))
	}
}
