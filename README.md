# aegis-proxy

A proxy server with OpenTelemetry tracing and OpenMetrics support for comprehensive observability.

## Features

- **Multi-type proxy support**: Ingress, egress, or combined ingress-egress proxy
- **JWT authentication**: Support for multiple identity providers (Kubernetes, Azure, AWS, HashiCorp Vault)
- **Policy enforcement**: Configurable ingress policies for access control
- **OpenTelemetry tracing**: Distributed tracing support with OTLP exporters
- **OpenMetrics support**: Prometheus-compatible metrics collection and endpoint

## Metrics

The proxy can expose metrics in OpenMetrics format for monitoring and observability:

### Available Metrics

- `aegis_proxy_requests_total`: Total number of HTTP requests processed (by proxy type, method, status code)
- `aegis_proxy_request_duration_seconds`: Request duration histogram (by proxy type, method)
- `aegis_proxy_auth_failures_total`: Authentication failure counts (by proxy type, reason)
- `aegis_proxy_policy_failures_total`: Policy validation failure counts (by proxy type, policy name)
- `aegis_proxy_active_connections`: Current active connections (by proxy type)

### Configuration

Metrics are disabled by default and can be enabled using CLI flags:

```bash
# Enable metrics on port 9090 (default)
aegis-proxy run --enable-metrics

# Enable metrics on custom port
aegis-proxy run --enable-metrics --metrics-port 8080
```

The metrics endpoint is available at `/metrics` and provides OpenMetrics-formatted output compatible with Prometheus.

## Usage

```bash
# Run ingress proxy with metrics
aegis-proxy run --type ingress --enable-metrics

# Run egress proxy with metrics 
aegis-proxy run --type egress --enable-metrics

# Run combined proxy with metrics on custom port
aegis-proxy run --type ingress-egress --enable-metrics --metrics-port 8080
```

## Health Endpoints

Health endpoints are available on all proxy servers:
- Ingress proxy: `http://localhost:3127/health`
- Egress proxy: `http://localhost:3128/health`