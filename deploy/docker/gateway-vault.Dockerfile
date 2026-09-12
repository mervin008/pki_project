# syntax=docker/dockerfile:1

# Built from the repository root, not from ./gateways/vault/.
#
# This is a Go workspace of six modules and every go.mod carries
# `replace github.com/certpilot/certpilot/pkg => ../pkg`. A build context
# rooted at the module cannot resolve that path, so the context is the whole
# tree and .dockerignore is what keeps it to source.
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY . .

# CGO off: the runtime stage is alpine and a cgo-linked binary would pick up a
# glibc dependency the image does not have. -trimpath keeps the build machine's
# paths out of the binary.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
      -o /out/gateway-vault ./gateways/vault/cmd/

FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

# Nothing here needs root, and a certificate tool running as root inside its own
# container is an argument it should not have to make.
RUN addgroup -S certpilot && adduser -S -G certpilot -h /app certpilot

WORKDIR /app
COPY --from=builder /out/gateway-vault /app/gateway-vault

USER certpilot

EXPOSE 9093

ENTRYPOINT ["/app/gateway-vault"]
CMD ["--port=9093"]
