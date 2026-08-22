# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY . .

RUN go build -o /app/bin/gateway-acme ./gateways/acme/cmd/

# Runtime stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/bin/gateway-acme /app/gateway-acme

EXPOSE 9092

ENTRYPOINT ["/app/gateway-acme"]
CMD ["--port=9092"]
