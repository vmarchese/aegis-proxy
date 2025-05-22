# aegis-proxy

Aegis Proxy is a versatile proxy designed to secure and manage access to services by handling token validation and policy enforcement.

## Features

*   **Ingress/Egress Proxying:** Can operate in ingress, egress, or combined ingress-egress modes.
*   **Identity Provider Integration:** Supports various identity providers like HashiCorp Vault, Azure, Kubernetes, and AWS for token issuance and public key retrieval.
*   **Policy Enforcement:** Allows defining and enforcing ingress policies based on identity claims and request paths/methods.
*   **OpenTelemetry Tracing:** Integrated with OpenTelemetry for distributed tracing.
*   **Prometheus Metrics:** Exposes detailed metrics for monitoring.

## Command-Line Flags

Aegis Proxy is configured via command-line flags. Here are some of the key flags:

*   `--inport`, `-i`: Port for the ingress proxy server (default: "3127").
*   `--outport`, `-o`: Port for the egress proxy server (default: "3128").
*   `--type`, `-t`: Type of proxy server to run (e.g., `ingress`, `egress`, `ingress-egress`, default: "ingress").
*   `--token`, `-k`: Path to the token file (default: "/var/run/secrets/tokens/token").
*   `--uuid`, `-u`: Unique ID for the proxy instance (default: auto-generated UUID).
*   `--identity`, `-n`: Identity name for the proxy itself when acting as a client (default: "aegisproxy").
*   `--identity-allowed`: Comma-separated list of identities allowed for incoming tokens.
*   `--identity-provider`, `-p`: Identity provider type (e.g., `hashicorpvault`, `azure`, `kubernetes`, `aws`, default: "hashicorpvault").
*   `--policy`, `-l`: Name of the IngressPolicy custom resource to enforce.
*   `--token-grace-period`, `-g`: Grace period for token expiry (default: 1 minute).
*   `--metrics-port`, `-m`: Port for the Prometheus metrics server (default: "9090").

Specific flags for identity providers (like `--vault-address`, `--azure-tenant-id`, etc.) are also available. Use `--help` to see all available flags.

## Metrics

Aegis Proxy exposes metrics in the OpenMetrics format, making it compatible with Prometheus for monitoring and alerting.

*   **Endpoint:** `/metrics`
*   **Default Port:** `9090`
*   **Configuration Flag:** `--metrics-port` or `-m`

### Key Metrics

Here are some of the key metrics exposed by Aegis Proxy:

*   **`http_requests_total`**
    *   Description: Total number of HTTP requests handled by the proxy.
    *   Labels:
        *   `proxy_type`: Type of the proxy handling the request (e.g., `ingress`, `egress`).
        *   `method`: HTTP method of the request (e.g., `GET`, `POST`).
        *   `code`: HTTP status code of the response (e.g., `200`, `401`, `500`).

*   **`http_request_duration_seconds`**
    *   Description: Histogram of HTTP request latencies in seconds.
    *   Labels:
        *   `proxy_type`: Type of the proxy handling the request.
        *   `method`: HTTP method of the request.

*   **`aegisproxy_token_validation_errors_total`**
    *   Description: Total number of token validation errors encountered by the ingress proxy.
    *   Labels:
        *   `proxy_type`: Should always be `ingress` for this metric.
        *   `reason`: The specific reason for the validation failure (e.g., `parse_failed`, `key_not_found`, `validation_failed`).

*   **`aegisproxy_policy_evaluation_total`**
    *   Description: Total number of policy evaluations performed by the ingress proxy.
    *   Labels:
        *   `proxy_type`: Should always be `ingress` for this metric.
        *   `decision`: The outcome of the policy evaluation (e.g., `allowed`, `denied`).

## Building and Running

(Details on building and running the proxy can be added here)

## Policy Configuration

(Details on how to configure IngressPolicy custom resources can be added here)