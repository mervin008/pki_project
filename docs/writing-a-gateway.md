# Writing a Custom Gateway Plugin

CertPilot uses a modular, gRPC-based plugin architecture. Anyone can write a gateway for any public or private Certificate Authority in any language (Go, Rust, Python, etc.) by implementing the protobuf contract in `proto/provider/v1/provider.proto`.

## The Gateway gRPC Contract

Every gateway implements `CertificateProviderService`:

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

## Step-by-Step Go Gateway Example

### 1. Create Gateway Directory
```bash
mkdir -p gateways/my-ca/cmd
```

### 2. Implement the Provider Interface
```go
package myca

import (
    "context"
    providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
    commonv1 "github.com/certpilot/certpilot/pkg/pb/common/v1"
)

type Provider struct {
    providerv1.UnimplementedCertificateProviderServiceServer
}

func (p *Provider) IssueCertificate(ctx context.Context, req *providerv1.IssueCertificateRequest) (*providerv1.IssueCertificateResponse, error) {
    // 1. Call CA API / Hardware HSM
    // 2. Return CertificateInfo
    return &providerv1.IssueCertificateResponse{...}, nil
}
```

### 3. Register in CertPilot
Once running on a port (e.g. `9093`), register the gateway in CertPilot dashboard or via API:
```bash
curl -X POST http://localhost:8080/api/v1/ca-accounts \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-custom-ca",
    "provider_type": "custom",
    "gateway_addr": "localhost:9093"
  }'
```
