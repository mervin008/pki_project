.PHONY: all build build-core build-gateways test test-frontend test-coverage lint proto proto-lint \
        dev dev-certs generate-kek run-core run-gateway-selfsigned run-gateway-acme run-frontend \
        clean help

# ── Variables ────────────────────────────────────────────
GO   := go
BUF  := buf
BIN  := bin
PKI  := .certpilot/pki
STATE := .certpilot/state

# Each component is its own Go module, so tooling has to iterate rather than
# rely on a single ./... from the repository root.
MODULES := pkg core gateways/selfsigned gateways/acme

CORE_BIN          := $(BIN)/certpilot-core
GW_SELFSIGNED_BIN := $(BIN)/gateway-selfsigned
GW_ACME_BIN       := $(BIN)/gateway-acme

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

# ── Setup ────────────────────────────────────────────────

## Generate a key encryption key. Certificate private keys and CA credentials
## are sealed with it before they reach the database.
generate-kek: build-core
	@$(CORE_BIN) --generate-kek

## Generate development mTLS material for the core-to-gateway channel.
## That channel carries CSRs, private keys, and CA credentials, so it is
## mutually authenticated by default; this makes turning it on a single command.
dev-certs: build-core
	@$(CORE_BIN) --generate-dev-certs=$(PKI)

## Apply outstanding database migrations. Reads CERTPILOT_DB_URL (or DATABASE_URL);
## override with `make migrate DB=postgres://...`.
##
## Deliberately not run by the server on startup: a schema change should be
## something an operator decides to do, not a side effect of a replica restarting
## mid-deploy while older replicas are still reading the old shape.
migrate: build-core
	@$(CORE_BIN) --migrate $(if $(DB),--db=$(DB),)

# ── Run (Development) ───────────────────────────────────
#
# Each of these runs in its own terminal. Run `make dev-certs` first.

## Start the local gateway, API, and frontend in one terminal.
dev:
	./scripts/dev.sh

run-core:
	$(GO) run ./core/cmd/ --config=config.dev.yaml

run-gateway-selfsigned:
	$(GO) run ./gateways/selfsigned/cmd/ \
		--port=9091 \
		--tls-cert=$(PKI)/gateway.pem \
		--tls-key=$(PKI)/gateway-key.pem \
		--tls-ca=$(PKI)/ca.pem

run-gateway-acme:
	$(GO) run ./gateways/acme/cmd/ \
		--port=9092 \
		--directory=letsencrypt-staging \
		--state-dir=$(STATE)/acme \
		--tls-cert=$(PKI)/gateway.pem \
		--tls-key=$(PKI)/gateway-key.pem \
		--tls-ca=$(PKI)/ca.pem

run-frontend:
	cd frontend && npm run dev

# ── Test ─────────────────────────────────────────────────
test:
	@for m in $(MODULES); do \
		echo "==> $$m"; \
		(cd $$m && $(GO) test ./... -cover) || exit 1; \
	done

test-race:
	@for m in $(MODULES); do \
		echo "==> $$m"; \
		(cd $$m && $(GO) test ./... -race) || exit 1; \
	done

## Typecheck the frontend and check the hand-rolled SSE parser.
## Needs Node 22.18+ — the check imports TypeScript directly, using Node's own
## type stripping rather than adding a test runner to the dependency tree.
test-frontend:
	cd frontend && npx vue-tsc --noEmit && node scripts/check-sse.mjs

test-coverage:
	@for m in $(MODULES); do \
		(cd $$m && $(GO) test ./... -coverprofile=coverage.out && $(GO) tool cover -func=coverage.out | tail -1); \
	done

lint:
	@for m in $(MODULES); do \
		echo "==> $$m"; \
		(cd $$m && $(GO) vet ./...) || exit 1; \
	done
	@gofmt -l $(MODULES) | grep . && echo "gofmt needed on the files above" && exit 1 || true

tidy:
	@for m in $(MODULES); do (cd $$m && $(GO) mod tidy); done

# ── Clean ────────────────────────────────────────────────
clean:
	rm -rf $(BIN)/
	rm -f coverage.out coverage.html
	@for m in $(MODULES); do rm -f $$m/coverage.out; done

## Also removes development keys and ACME account state.
clean-all: clean
	rm -rf .certpilot/

# ── Help ─────────────────────────────────────────────────
help:
	@echo "CertPilot"
	@echo ""
	@echo "Setup"
	@echo "  make dev-certs               Generate development mTLS material"
	@echo "  make generate-kek            Print a new CERTPILOT_KEK"
	@echo ""
	@echo "Build"
	@echo "  make build                   Build all binaries"
	@echo "  make proto                   Generate protobuf Go code"
	@echo ""
	@echo "Run (one per terminal)"
	@echo "  make dev                      Start the complete local development stack"
	@echo "  make run-core                CertPilot Core        :8080"
	@echo "  make run-gateway-selfsigned  Self-signed gateway   :9091"
	@echo "  make run-gateway-acme        ACME gateway          :9092"
	@echo "  make run-frontend            Vue frontend          :3000"
	@echo ""
	@echo "Check"
	@echo "  make test                    Run all tests"
	@echo "  make test-race               Run all tests under the race detector"
	@echo "  make test-frontend           Typecheck the UI and check the SSE parser"
	@echo "  make lint                    go vet and gofmt"
	@echo ""
	@echo "Clean"
	@echo "  make clean                   Remove build artifacts"
	@echo "  make clean-all               Also remove development keys and ACME state"
