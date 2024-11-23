package traces

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/trace"
)

func newGRPCExporter(ctx context.Context, options []Option) (trace.SpanExporter, error) {
	grpcOptions := []otlptracegrpc.Option{
		otlptracegrpc.WithInsecure(),
	} // default here
	if len(options) != 0 {
		for _, o := range options {
			grpcOpt, ok := o.(otlptracegrpc.Option)
			if !ok {
				return nil, fmt.Errorf("error in casting option to otlptracehttp.Option")
			}
			grpcOptions = append(grpcOptions, grpcOpt)
		}
	}

	return otlptrace.New(ctx, otlptracegrpc.NewClient(grpcOptions...))
}
