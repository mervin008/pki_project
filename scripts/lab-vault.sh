#!/usr/bin/env bash
#
# Build a Vault PKI for the gateway's live tests to run against.
#
# Creates a root, two issuing CAs — one healthy and one three weeks from
# expiry — a role that keeps no copy of what it signs, and an AppRole identity
# scoped to those mounts. The expiring CA is the point: Vault refuses to sign a
# certificate that would outlive its issuer, and that refusal is the one thing
# about this gateway that could not be verified against a fake.
#
# Usage:
#
#   vault server -dev -dev-root-token-id=certpilot-dev-root &
#   ./scripts/lab-vault.sh
#   eval "$(./scripts/lab-vault.sh --env)"
#   go test ./gateways/vault/ -run Live -v
#
# The dev server keeps everything in memory, so stopping it is the cleanup.
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-certpilot-dev-root}"
WORK="${TMPDIR:-/tmp}/certpilot-lab-vault"
mkdir -p "$WORK"

# --env prints the variables the live tests read, for an already-built lab.
if [ "${1:-}" = "--env" ]; then
  echo "export CERTPILOT_TEST_VAULT_ADDR=$VAULT_ADDR"
  echo "export CERTPILOT_TEST_VAULT_ROLE_ID=$(cat "$WORK/role_id")"
  echo "export CERTPILOT_TEST_VAULT_SECRET_ID=$(cat "$WORK/secret_id")"
  exit 0
fi

vault secrets enable -path=pki pki >/dev/null
vault secrets tune -max-lease-ttl=87600h pki >/dev/null
vault write -field=certificate pki/root/generate/internal \
  common_name="CertPilot Lab Root CA" issuer_name="lab-root" ttl=87600h > "$WORK/root.pem"
echo "root CA issued"

make_intermediate() {
  local mount=$1 cn=$2 ttl=$3
  vault secrets enable -path="$mount" pki >/dev/null
  vault secrets tune -max-lease-ttl="$ttl" "$mount" >/dev/null
  vault write -field=csr "$mount/intermediate/generate/internal" \
    common_name="$cn" key_type=ec key_bits=256 > "$WORK/$mount.csr"
  vault write -field=certificate pki/root/sign-intermediate \
    issuer_ref="lab-root" csr=@"$WORK/$mount.csr" format=pem_bundle ttl="$ttl" > "$WORK/$mount.pem"
  vault write "$mount/intermediate/set-signed" certificate=@"$WORK/$mount.pem" >/dev/null
  vault write "$mount/roles/web" \
    allowed_domains="example.com" allow_subdomains=true \
    max_ttl=2160h key_type=ec key_bits=256 >/dev/null
  echo "$mount ready ($cn, ttl $ttl)"
}

make_intermediate pki-int    "CertPilot Lab Issuing CA"       43800h
make_intermediate pki-expiry "CertPilot Lab Expiring Issuing" 504h

# Where a client would look for the CRL. Set after the issuers exist, which is
# also the ordinary case: their own certificates carry no CRL, so the gateway
# has to fall back to the mount's configuration to report one.
vault write pki-int/config/urls \
  issuing_certificates="$VAULT_ADDR/v1/pki-int/ca" \
  crl_distribution_points="$VAULT_ADDR/v1/pki-int/crl" \
  ocsp_servers="$VAULT_ADDR/v1/pki-int/ocsp" >/dev/null

# A role Vault keeps no copy from: its certificates cannot be looked up by
# serial, and can still be revoked by handing Vault the certificate.
vault write pki-int/roles/ephemeral \
  allowed_domains="example.com" allow_subdomains=true \
  max_ttl=720h key_type=ec no_store=true >/dev/null
echo "pki-int/roles/ephemeral ready (no_store)"

vault auth enable approle >/dev/null
vault policy write certpilot - >/dev/null <<POLICY
path "pki-int/*"    { capabilities = ["read", "list", "create", "update"] }
path "pki-expiry/*" { capabilities = ["read", "list", "create", "update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
POLICY
vault write auth/approle/role/certpilot \
  token_policies="certpilot" token_ttl=1h token_max_ttl=4h >/dev/null
vault read -field=role_id auth/approle/role/certpilot/role-id > "$WORK/role_id"
vault write -f -field=secret_id auth/approle/role/certpilot/secret-id > "$WORK/secret_id"

echo
echo "lab ready. To run the live tests:"
echo "  eval \"\$(./scripts/lab-vault.sh --env)\""
echo "  go test ./gateways/vault/ -run Live -v"
