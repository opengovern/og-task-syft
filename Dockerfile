# Build stage
FROM golang:1.23-alpine AS build

# Install required dependencies
RUN apk --no-cache add ca-certificates curl git tar

# Install Grype (installs latest stable by default)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Create a /tmp directory since scratch doesn't have one
RUN chmod 1777 /tmp

# Build your Go binary
WORKDIR /app
COPY . .
RUN go build -o og-task-syft main.go

# Final minimal image
FROM scratch

# Copy CA certificates
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy Grype binary
COPY --from=build /usr/local/bin/syft /usr/local/bin/syft

# Copy /tmp directory
COPY --from=build /tmp /tmp

# Copy og-task-syft binary
COPY --from=build /app/og-task-syft /og-task-syft

# Set a generic entrypoint to Grype so any arguments can be passed at runtime
ENTRYPOINT ["/usr/local/bin/syft"]
