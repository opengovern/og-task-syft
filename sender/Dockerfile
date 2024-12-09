# Do not change the code below
# Run The Sender Go Application
FROM golang:1.23-alpine 
# Copy the source code
COPY . .
# Download the dependencies
RUN go mod download
# Build the Go application
RUN  go build -o sender .
ENTRYPOINT ["/sender"]