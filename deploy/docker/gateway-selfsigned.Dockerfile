# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY . .

RUN go build -o /app/bin/gateway-selfsigned ./gateways/selfsigned/cmd/

# Runtime stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/bin/gateway-selfsigned /app/gateway-selfsigned

EXPOSE 9091

ENTRYPOINT ["/app/gateway-selfsigned"]
CMD ["--port=9091"]
