# Use the official Golang image as a build stage
FROM golang:1.23 AS builder

ARG GOVERSION
ARG VERSION
ARG BUILDUSER
ARG BUILDTIME

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the go.mod and go.sum files
COPY go.mod go.sum ./


# Copy the source code into the container
COPY cmd/ cmd/
COPY internal/ internal/

# Build the Go app with CGO disabled to ensure a statically linked binary
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X 'main.Version=${VERSION}' \
    -X 'main.GoVersion=${GOVERSION}' \
    -X 'main.BuildUser=${BUILDUSER}' \
    -X 'main.BuildTime=${BUILDTIME}'" \
    -o aegisproxy aegisproxy.io/aegis-proxy/cmd/aegisproxy

# Start a new stage from scratch
FROM alpine:latest

RUN apk add iptables tcpdump

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/aegisproxy .

# Expose port 8080 to the outside world
EXPOSE 3128

# Command to run the executable
CMD ["./aegisproxy"]
