# Do not change the code below
# Run The Sender Go Application
FROM golang:1.23-alpine 
# Copy the source code
COPY . .
# Download the dependencies
RUN cd sender && go mod download -x
# Build the Go application
RUN cd sender &&   go build -o sender .

ENTRYPOINT ["./sender/sender"]