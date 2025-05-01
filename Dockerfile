FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy Go module files
COPY src/go.mod src/go.sum ./
RUN go mod download

# Copy source code
COPY src/ ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o form-service .

# Second stage for a smaller image
FROM alpine:3.18

WORKDIR /app

# Copy the compiled application from the builder stage
COPY --from=builder /app/form-service .

# Expose the port
EXPOSE 8080

# Set environment variables
ENV GIN_MODE=release

# Start the application
CMD ["./form-service"]
