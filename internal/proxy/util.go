package proxy

import (
	"net/http"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func HTTPError(w http.ResponseWriter, code int, err error, span trace.Span) {
	http.Error(w, err.Error(), code)
	span.SetStatus(codes.Error, err.Error())
	span.RecordError(err)
}
