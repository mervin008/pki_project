# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY . .

RUN go build -o /app/bin/gateway-vault ./gateways/vault/cmd/

# Runtime stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/bin/gateway-vault /app/gateway-vault

EXPOSE 9093

ENTRYPOINT ["/app/gateway-vault"]
CMD ["--port=9093"]
