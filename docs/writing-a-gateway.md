# Writing a gateway

A gateway is a standalone process that teaches CertPilot how to talk to one
certificate authority. It implements a single gRPC service, so it can be written
in any language with protobuf support.

The contract is [`proto/provider/v1/provider.proto`](../proto/provider/v1/provider.proto).
[`gateways/selfsigned`](../gateways/selfsigned) is the smallest complete
implementation; [`gateways/acme`](../gateways/acme) is the realistic one.

## The contract

```protobuf
service CertificateProviderService {
  rpc IssueCertificate(IssueCertificateRequest) returns (IssueCertificateResponse);
  rpc RenewCertificate(RenewCertificateRequest) returns (RenewCertificateResponse);
  rpc RevokeCertificate(RevokeCertificateRequest) returns (RevokeCertificateResponse);
  rpc GetCertificateStatus(GetCertificateStatusRequest) returns (GetCertificateStatusResponse);
  rpc GetCAInfo(GetCAInfoRequest) returns (GetCAInfoResponse);
  rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse);
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
  rpc ValidateConfig(ValidateConfigRequest) returns (ValidateConfigResponse);
}
```

## Rules that matter

These are not style preferences. Each one exists because violating it produces a
failure that looks like success, which is the worst kind of bug a certificate
tool can have.

**Never report success for work you did not do.** If `RevokeCertificate` returns
`success: true` without revoking, an operator handling a key compromise will
believe a live certificate is dead. Return an error. The core marks records
`RENEWAL_FAILED` and surfaces the message — that is the desired outcome, not
something to paper over.

**Return a certificate, not a placeholder.** `certificate_pem` must be a parseable
X.509 certificate. The core parses it before storing and rejects anything else
with a 502, so returning a CSR or an empty buffer fails loudly rather than
producing a record marked `ISSUED` that cannot serve traffic.

**Rotate the key on renewal.** ACME has no distinct renewal operation and neither
do most APIs — a renewal is a fresh issuance. Reusing the key means a key
compromise is never resolved by renewing.

**Prefer the caller's CSR.** When `csr_pem` is set, use it and return no
`private_key_pem`. The key then stays wherever it was generated, which is the
best outcome available. Generate a key only when no CSR is supplied.

**Treat `provider_config` as a secret.** It arrives decrypted for exactly one
call and contains API tokens and account credentials. Never log it, never
include it in an error message.

**Be idempotent where the CA allows it.** Revoking an already-revoked certificate
should report success — otherwise a cleanup workflow that runs twice fails the
second time for no useful reason.

**Validate before the core stores anything.** `ValidateConfig` is called when an
operator registers a CA account. Check credentials, reach the CA, and return
specific errors. Catching a wrong DNS token here costs a moment; catching it
during a renewal costs an outage.

**Advertise only what you implement.** `GetCapabilities` drives what the core and
the UI offer. Listing `tls-alpn-01` without a solver turns a configuration-time
error into a failure at the CA.

## A minimal Go gateway

```bash
mkdir -p gateways/my-ca/cmd
cd gateways/my-ca && go mod init github.com/certpilot/certpilot/gateways/my-ca
```

Add it to `go.work` and to `MODULES` in the `Makefile`.

```go
package myca

import (
    "context"
    "fmt"

    commonv1 "github.com/certpilot/certpilot/pkg/pb/common/v1"
    providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
    "github.com/certpilot/certpilot/pkg/x509util"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
    "google.golang.org/protobuf/types/known/timestamppb"
)

// Config is whatever this CA needs. It arrives as provider_config JSON,
// stored encrypted by the core.
type Config struct {
    Endpoint string `json:"endpoint"`
    APIToken string `json:"api_token"`
}

type Provider struct {
    providerv1.UnimplementedCertificateProviderServiceServer
}

func (p *Provider) IssueCertificate(
    ctx context.Context,
    req *providerv1.IssueCertificateRequest,
) (*providerv1.IssueCertificateResponse, error) {
    cfg, err := parseConfig(req.ProviderConfig)
    if err != nil {
        return nil, status.Error(codes.InvalidArgument, err.Error())
    }
    if len(req.Domains) == 0 {
        return nil, status.Error(codes.InvalidArgument, "at least one domain is required")
    }

    // Use the caller's CSR when supplied, so their key never travels.
    csrDER, keyPEM, err := prepareCSR(req)
    if err != nil {
        return nil, status.Error(codes.InvalidArgument, err.Error())
    }

    leafPEM, chainPEM, err := cfg.issue(ctx, csrDER)
    if err != nil {
        return nil, status.Error(codes.Internal, fmt.Sprintf("CA rejected the request: %v", err))
    }

    // Report what the certificate says, not what was requested.
    info, err := x509util.ParseCertificatePEM(leafPEM)
    if err != nil {
        return nil, status.Error(codes.Internal, "the CA returned an unparseable certificate")
    }

    return &providerv1.IssueCertificateResponse{
        Certificate: &commonv1.CertificateInfo{
            CommonName:        info.CommonName,
            Sans:              info.SANs,
            SerialNumber:      info.SerialNumber,
            IssuerDn:          info.IssuerDN,
            NotBefore:         timestamppb.New(info.NotBefore),
            NotAfter:          timestamppb.New(info.NotAfter),
            KeyType:           info.KeyType,
            KeySize:           int32(info.KeySize),
            FingerprintSha256: info.FingerprintSHA256,
            CertificatePem:    leafPEM,
            ChainPem:          chainPEM,
            PrivateKeyPem:     keyPEM, // nil when the caller supplied a CSR
        },
        ProviderCertificateId: info.SerialNumber,
    }, nil
}
```

The entrypoint mirrors the existing gateways:

```go
func main() {
    port := flag.Int("port", 9093, "gRPC server port")
    tlsCert := flag.String("tls-cert", "", "path to this gateway's TLS certificate")
    tlsKey := flag.String("tls-key", "", "path to this gateway's TLS private key")
    tlsCA := flag.String("tls-ca", "", "CA bundle used to verify the core")
    insecure := flag.Bool("insecure", false, "serve without TLS — development only")
    flag.Parse()

    tlsCfg := grpckit.TLSConfig{
        CertFile: *tlsCert, KeyFile: *tlsKey, CAFile: *tlsCA, Insecure: *insecure,
    }

    opts := grpckit.DefaultServerOptions()
    opts.Port = *port
    opts.TLS = tlsCfg

    server, err := grpckit.NewServer(opts)
    if err != nil {
        slog.Error("failed to create gRPC server", "error", err)
        os.Exit(1)
    }

    providerv1.RegisterCertificateProviderServiceServer(server, myca.NewProvider())
    if err := grpckit.Serve(server, *port); err != nil {
        slog.Error("gateway failed", "error", err)
        os.Exit(1)
    }
}
```

`grpckit` handles mutual TLS, health checks, and keepalives. Non-Go gateways
must do the same: TLS 1.3, present a certificate, verify the core's certificate
against the shared CA, and require client certificates.

## Error codes

The core uses the gRPC code to tell a retryable failure from a permanent one.

| Code | Use for |
|:---|:---|
| `InvalidArgument` | Bad request or configuration — the caller must change something |
| `FailedPrecondition` | Domain validation failed, no usable challenge |
| `ResourceExhausted` | CA rate limit — back off |
| `Unavailable` | CA unreachable or timed out — retry later |
| `Internal` | Everything else |

## Registering

```bash
curl -X POST localhost:8080/api/v1/ca-accounts \
  -H 'Content-Type: application/json' -d '{
    "name": "my-ca",
    "provider_type": "custom",
    "gateway_addr": "localhost:9093",
    "server_name": "localhost",
    "config": {"endpoint": "https://ca.example.com", "api_token": "..."}
  }'
```

The core dials over mTLS, calls `GetCapabilities`, then `ValidateConfig`. If
validation fails, nothing is stored and the errors come back to the operator.

## Testing

Test against a local CA rather than a real one. [Pebble](https://github.com/letsencrypt/pebble)
is the reference for ACME; most commercial CAs offer a sandbox. Cover at minimum:

- Issuance returns a parseable certificate
- Malformed configuration is rejected by `ValidateConfig`
- Revocation of an unparseable certificate fails rather than reporting success
- Capabilities list only implemented features

See [`gateways/acme/provider_test.go`](../gateways/acme/provider_test.go) for
the shape.

## Post-quantum

Do not hardcode an algorithm list. Migration `002` replaced the schema's
`key_type` CHECK constraints with a `key_algorithms` table precisely so
ML-DSA, SLH-DSA, and composite certificates can be added by insert.

If your CA can issue post-quantum or composite certificates today — Vault,
step-ca, AWS Private CA, EJBCA — say so in `supported_key_types` using the
names in `key_algorithms`, and add any missing ones there. Private PKI is where
PQC is usable now; publicly trusted ACME CAs cannot issue it yet.
