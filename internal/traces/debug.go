package traces

import (
	"context"
	"os"

	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"
)

func newDebugExporter(ctx context.Context, options []Option) (trace.SpanExporter, error) {
	return stdouttrace.New(
		stdouttrace.WithWriter(os.Stdout),
		stdouttrace.WithPrettyPrint(),
	)
}
