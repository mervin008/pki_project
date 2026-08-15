# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY . .

RUN go build -o /app/bin/certpilot-core ./core/cmd/

# Runtime stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/bin/certpilot-core /app/certpilot-core
COPY config.example.yaml /app/config.example.yaml

EXPOSE 8080

ENTRYPOINT ["/app/certpilot-core"]
CMD ["--config=/app/config.example.yaml"]
