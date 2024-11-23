package traces

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/contrib/propagators/autoprop"
	"go.opentelemetry.io/otel"
	_ "go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	_ "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	_ "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type ContextKey string

const SuppressInstrumentation ContextKey = "traces.suppress"

type Option interface{}
type ExporterFunc func(context.Context, []Option) (sdktrace.SpanExporter, error)

type ExporterType string

const (
	GRPCExporterType  ExporterType = "grpc"
	HTTPExporterType  ExporterType = "http"
	DebugExporterType ExporterType = "debug"

	DefaultExporterType ExporterType = "grpc"

	EndpointResourceAttribute string = "traces.endpoint"
	DefaultEndpoint           string = "0.0.0.0:4317"

	EnvTracesExporter         string = "OTEL_TRACES_EXPORTER"
	EnvTracesExporterEndpoint string = "OTEL_TRACES_EXPORTER_ENDPOINT"
)

var exporterFuncMap = map[ExporterType]ExporterFunc{
	GRPCExporterType:  newGRPCExporter,
	HTTPExporterType:  newHTTPExporter,
	DebugExporterType: newDebugExporter,
}

type Provider struct {
	tracerProvider trace.TracerProvider
}

func New(ctx context.Context, options ...Option) (*Provider, error) {
	exporterType := DefaultExporterType

	p := &Provider{}

	if os.Getenv(EnvTracesExporter) != "" {
		exporterType = ExporterType(os.Getenv(EnvTracesExporter))
	}

	if exporterFuncMap[exporterType] == nil {
		return nil, fmt.Errorf("invalid exporter type: %s", exporterType)
	}

	traceExporter, err := exporterFuncMap[exporterType](ctx, options)
	if err != nil {
		return nil, err
	}

	r, err := sdkresource.New(ctx, sdkresource.WithFromEnv())
	if err != nil {
		return nil, err
	}

	p.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(r),
	)

	otel.SetTextMapPropagator(autoprop.NewTextMapPropagator())
	otel.SetTracerProvider(p.tracerProvider)

	return p, nil

}

func (p *Provider) GetTracerProvider() trace.TracerProvider {
	return p.tracerProvider
}
func (p *Provider) Shutdown(ctx context.Context) error {
	return nil
}
