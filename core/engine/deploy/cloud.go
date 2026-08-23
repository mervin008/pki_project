package deploy

import (
	"context"
	"fmt"
	"strings"

	"github.com/certpilot/certpilot/core/engine/cloudsync"
)

// The cloud deployers.
//
// All three of these — ACM, Key Vault, and F5 — get the same thing wrong in
// three different vocabularies, and it is worth naming once because every one
// of them *succeeds* while getting it wrong:
//
//		Installing the certificate is the easy half. Installing it as the thing
//		that is already being served is the job.
//
//	  - ACM's ImportCertificate without a CertificateArn creates a new
//	    certificate with a new ARN. Every listener and distribution still points
//	    at the old ARN and still serves the old certificate.
//	  - A Key Vault import under a new name creates a certificate nothing is
//	    configured to read, beside the one everything is.
//	  - An F5 certificate installed under a new name sits in the crypto store
//	    while the client-SSL profile on the virtual server carries on with the
//	    previous one.
//
// In all three cases the API returns 200, the deployment is recorded as a
// success, the provider's console shows a fresh green certificate, and the
// thing in front of the users expires on schedule. That is precisely the
// failure this product exists to prevent, available as a single omitted field.
//
// So the identifier of the thing being replaced is required, per binding, and
// refused at binding time rather than at deploy time.
const (
	TypeACM      = "aws_acm"
	TypeKeyVault = "azure_key_vault"
	TypeF5       = "f5"
)

// connectionField is the target config key naming a cloud connection.
//
// Cloud deployers borrow the credentials of a connection rather than storing
// their own copy. Two copies of one AWS key — one in cloud_connections for
// discovery, one in deployment_targets for deployment — is one rotation away
// from a system that reads an account it can no longer write to, and the
// failure surfaces at the worst possible moment.
//
// It also closes a loop this project opened. Phase 5's headline finding is that
// an *imported* ACM certificate is never renewed by AWS, and everybody believes
// otherwise. The account that finding came from is the account this deploys to.
const connectionField = "connection_id"

// MergeConnection overlays a cloud connection's configuration onto a target's.
//
// The connection wins on a collision, always. A target may carry placement of
// its own, but it must never be able to override the credentials or the region
// of the account somebody registered — otherwise "which account does this write
// to" has two answers and the one in the sealed blob is the one that counts.
//
// The result is what gets *validated* and what gets handed to the deployer. It
// is deliberately not what gets stored: the target seals its own config only,
// so registering an account twice remains impossible rather than merely
// discouraged.
func MergeConnection(targetConfig, connectionConfig map[string]any) map[string]any {
	merged := make(map[string]any, len(targetConfig)+len(connectionConfig))
	for k, v := range targetConfig {
		merged[k] = v
	}
	for k, v := range connectionConfig {
		merged[k] = v
	}
	if id := configString(targetConfig, connectionField); id != "" {
		merged[connectionField] = id
	}
	return merged
}

// ConnectionID returns the cloud connection a target's config names, if any.
func ConnectionID(config map[string]any) string {
	return configString(config, connectionField)
}

// RequiresConnection reports whether this target type borrows a cloud
// connection's credentials.
func RequiresConnection(targetType string) bool {
	switch strings.TrimSpace(strings.ToLower(targetType)) {
	case TypeACM, TypeKeyVault:
		return true
	}
	return false
}

// ── AWS Certificate Manager ─────────────────────────────────

type acmDeployer struct {
	client *cloudsync.ACM
	region string
}

func newACMDeployer(config map[string]any) (Deployer, error) {
	if configString(config, connectionField) == "" {
		return nil, missingField(TypeACM, connectionField,
			"the id of the AWS connection whose credentials to use; create one under cloud connections rather than pasting a second copy of the same key here")
	}
	client, err := cloudsync.NewACM(config)
	if err != nil {
		return nil, err
	}
	return &acmDeployer{client: client, region: client.Region()}, nil
}

func (a *acmDeployer) Type() string { return TypeACM }

func (a *acmDeployer) Describe() string {
	return fmt.Sprintf("AWS Certificate Manager in %s", a.region)
}

// NeedsPrivateKey is true and cannot be otherwise: ACM stores the key with the
// certificate, which is the whole reason a load balancer can terminate TLS with
// it. This target therefore appears in the answer to "where does this
// organisation ship private keys", correctly.
func (a *acmDeployer) NeedsPrivateKey() bool { return true }

func (a *acmDeployer) Deploy(ctx context.Context, b Bundle) (string, error) {
	arn := optionString(b.Options, "certificate_arn")
	if arn == "" {
		// Belt and braces; the binding refuses this at creation. Reaching here
		// means a binding was written by something other than the API, and
		// importing without an ARN would create a certificate attached to
		// nothing while reporting success.
		return "", fmt.Errorf(
			"this deployment has no certificate_arn, and importing without one would create a new ACM certificate that no load balancer is pointing at")
	}

	returned, err := a.client.ImportCertificate(ctx, arn, b.CertificatePEM, b.PrivateKeyPEM, b.ChainPEM)
	if err != nil {
		return "", err
	}
	if returned != arn {
		// ACM answering with a different ARN means it created rather than
		// replaced, which is the failure above happening anyway. Reported as an
		// error even though the call succeeded, because a success here would be
		// a deployment nothing is serving.
		return "", fmt.Errorf(
			"ACM created a new certificate (%s) instead of replacing %s. Nothing is pointing at the new one; whatever was using the old ARN is still serving the previous certificate",
			returned, arn)
	}

	detail := fmt.Sprintf("reimported %s into %s", shortARN(arn), a.Describe())
	// Read back rather than assumed. ACM accepting an import is not ACM having
	// made it live, and InUseBy is the only thing that says whether this
	// certificate is attached to anything at all.
	if status, inUseBy, err := a.client.DescribeCertificate(ctx, arn); err == nil {
		switch {
		case len(inUseBy) > 0:
			detail += fmt.Sprintf(" (%s, in use by %d resource(s))", strings.ToLower(status), len(inUseBy))
		default:
			detail += fmt.Sprintf(" (%s, and AWS reports nothing using it — this ARN may not be attached to a listener)",
				strings.ToLower(status))
		}
	}
	return detail, nil
}

// ── Azure Key Vault ─────────────────────────────────────────

type keyVaultDeployer struct {
	client *cloudsync.KeyVault
}

func newKeyVaultDeployer(config map[string]any) (Deployer, error) {
	if configString(config, connectionField) == "" {
		return nil, missingField(TypeKeyVault, connectionField,
			"the id of the Azure connection whose credentials to use; create one under cloud connections rather than pasting a second copy of the same secret here")
	}
	client, err := cloudsync.NewKeyVault(config)
	if err != nil {
		return nil, err
	}
	return &keyVaultDeployer{client: client}, nil
}

func (k *keyVaultDeployer) Type() string { return TypeKeyVault }

func (k *keyVaultDeployer) Describe() string { return k.client.VaultURL() }

func (k *keyVaultDeployer) NeedsPrivateKey() bool { return true }

func (k *keyVaultDeployer) Deploy(ctx context.Context, b Bundle) (string, error) {
	name := optionString(b.Options, "certificate_name")
	if name == "" {
		return "", fmt.Errorf(
			"this deployment has no certificate_name, and importing under a new one would leave whatever reads the existing name on the previous certificate")
	}

	id, err := k.client.ImportCertificate(ctx, name, b.CertificatePEM, b.PrivateKeyPEM, b.ChainPEM)
	if err != nil {
		return "", err
	}
	// The version is the part worth recording. Anything holding a versionless
	// identifier follows the latest automatically; anything pinned to a version
	// does not, and will go on serving the old one.
	return fmt.Sprintf("imported %s as a new version of %q (%s)", b.CommonName, name, id), nil
}

// ── Helpers ─────────────────────────────────────────────────

// optionString reads a binding's placement field.
func optionString(options map[string]any, key string) string {
	if v, ok := options[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// shortARN renders an ARN as its tail, which is what identifies it to a person.
func shortARN(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i+1 < len(arn) {
		return "…/" + arn[i+1:]
	}
	return arn
}
