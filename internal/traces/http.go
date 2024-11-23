package traces

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/trace"
)

func newHTTPExporter(ctx context.Context, options []Option) (trace.SpanExporter, error) {
	httpOptions := []otlptracehttp.Option{
		otlptracehttp.WithInsecure(),
	} // default here

	if len(options) != 0 {
		for _, o := range options {
			httpOpt, ok := o.(otlptracehttp.Option)
			if !ok {
				return nil, fmt.Errorf("error in casting option to otlptracehttp.Option")
			}
			httpOptions = append(httpOptions, httpOpt)
		}
	}

	return otlptrace.New(ctx, otlptracehttp.NewClient(httpOptions...))

}
