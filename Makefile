.PHONY: all build build-core build-gateways test lint proto clean run-core run-gateway-selfsigned run-gateway-acme

# ── Variables ────────────────────────────────────────────
GO := go
BUF := buf
CORE_BIN := bin/certpilot-core
GW_SELFSIGNED_BIN := bin/gateway-selfsigned
GW_ACME_BIN := bin/gateway-acme

# ── Build ────────────────────────────────────────────────
all: proto build

build: build-core build-gateways

build-core:
	$(GO) build -o $(CORE_BIN) ./core/cmd/

build-gateways: build-gateway-selfsigned build-gateway-acme

build-gateway-selfsigned:
	$(GO) build -o $(GW_SELFSIGNED_BIN) ./gateways/selfsigned/cmd/

build-gateway-acme:
	$(GO) build -o $(GW_ACME_BIN) ./gateways/acme/cmd/

# ── Proto ────────────────────────────────────────────────
proto:
	$(BUF) generate

proto-lint:
	$(BUF) lint

# ── Run (Development) ───────────────────────────────────
run-core:
	$(GO) run ./core/cmd/ --config=config.dev.yaml

run-gateway-selfsigned:
	$(GO) run ./gateways/selfsigned/cmd/ --port=9091

run-gateway-acme:
	$(GO) run ./gateways/acme/cmd/ --port=9092

run-frontend:
	cd frontend && npm run dev

# ── Test ─────────────────────────────────────────────────
test:
	$(GO) test ./pkg/... ./core/... ./gateways/selfsigned/... ./gateways/acme/... -v -cover

test-coverage:
	$(GO) test ./pkg/... ./core/... ./gateways/selfsigned/... ./gateways/acme/... -coverprofile=coverage.out
	$(GO) tool cover -html=coverage.out -o coverage.html

# ── Clean ────────────────────────────────────────────────
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# ── Help ─────────────────────────────────────────────────
help:
	@echo "CertPilot Makefile"
	@echo ""
	@echo "  make build                 Build all binaries"
	@echo "  make proto                 Generate protobuf Go code"
	@echo "  make run-core              Run CertPilot Core"
	@echo "  make run-gateway-selfsigned Run Self-Signed Gateway (port 9091)"
	@echo "  make run-gateway-acme      Run ACME Gateway (port 9092)"
	@echo "  make run-frontend          Run Vue frontend (npm run dev)"
	@echo "  make test                  Run all tests"
	@echo "  make clean                 Clean build artifacts"
