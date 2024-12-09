# Do not change the code below
# Run The Sender Go Application
FROM golang:1.23-alpine AS Final
# Copy and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .
# Build the Go application
RUN  go build -o sender .
ENTRYPOINT ["/sender"]