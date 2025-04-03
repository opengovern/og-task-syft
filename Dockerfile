# Build stage
FROM golang:1.23-alpine AS build

# Install required dependencies for build and syft install
# git is needed for go modules, curl/tar for syft install
RUN apk --no-cache add ca-certificates curl git tar

# Set working directory for build
WORKDIR /app

# Copy go module files first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire project source code
COPY . .

# Install Syft into the build stage's path
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Build the Go binary statically for Alpine target
# Using -tags netgo ensures use of Go's internal network resolver
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-w -s -extldflags "-static"' -tags netgo -o /app/og-task-syft main.go

# Final minimal image stage
FROM alpine:latest

# Install necessary runtime dependencies: ca-certificates and docker client
# bash is often useful for debugging if needed, but can be removed for minimal size
RUN apk --no-cache add ca-certificates docker-cli bash

# Set non-root user for security (optional but recommended)
# RUN addgroup -S appgroup && adduser -S appuser -G appgroup
# USER appuser

# Set working directory in the final image
WORKDIR /app

# Copy necessary files from the build stage
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /usr/local/bin/syft /usr/local/bin/syft
COPY --from=build /app/og-task-syft /app/og-task-syft

# Set the entrypoint to the Go application
ENTRYPOINT ["/app/og-task-syft"]
