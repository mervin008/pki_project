package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// deployTimeout bounds one attempt at one target.
//
// Slightly longer than the HTTP client's own timeout so a deployer that does
// two calls — write, then reload — is not cut off between them, and short
// enough that a wedged target releases the worker long before its lease runs
// out and another replica picks the job up.
const deployTimeout = 2 * time.Minute

// Executor performs one deployment.
//
// Split from the queue for the same reason the renewal executor is: the queue's
// own behaviour — leases, retries, escalation — is the part most likely to be
// subtly wrong and least likely to be exercised by one working target.
type Executor struct {
	store   store.Store
	keyring *secrets.Keyring
	broker  *events.Broker
}

// NewExecutor creates a deployment executor. The broker may be nil, in which
// case no events are published.
func NewExecutor(s store.Store, kr *secrets.Keyring, broker *events.Broker) *Executor {
	return &Executor{store: s, keyring: kr, broker: broker}
}

// Deploy installs one certificate at one target and returns what happened.
//
// The order matters. Everything that can refuse — a disabled target, an
// unsupported type, a missing private key, a certificate with no PEM — refuses
// before a single byte is sent, because the failure modes on the far side are
// the expensive ones. A target that rejects half a bundle has already replaced
// what it was serving.
func (e *Executor) Deploy(ctx context.Context, job *store.DeploymentJob) (string, error) {
	binding, err := e.store.GetCertificateDeployment(ctx, job.DeploymentID)
	if err != nil {
		return "", fmt.Errorf("this deployment no longer exists: %w", err)
	}
	if !binding.IsEnabled {
		return "", fmt.Errorf("this deployment is switched off")
	}

	target, err := e.store.GetDeploymentTarget(ctx, binding.TargetID)
	if err != nil {
		return "", fmt.Errorf("the target for this deployment no longer exists: %w", err)
	}
	if !target.IsEnabled {
		// An error, not a silent skip. Somebody queued this, and a queue that
		// quietly discards work because a switch is off is a queue that lies
		// about what it did.
		return "", fmt.Errorf("target %q is switched off", target.Name)
	}

	cert, err := e.store.GetCertificate(ctx, job.CertificateID)
	if err != nil {
		return "", fmt.Errorf("the certificate for this deployment no longer exists: %w", err)
	}
	if cert.CertificatePEM == nil || *cert.CertificatePEM == "" {
		return "", fmt.Errorf(
			"%s has no certificate body stored, so there is nothing to install. Certificates found by a scan are recorded from what an endpoint presented and may not include one",
			cert.CommonName)
	}

	deployer, err := e.buildDeployer(ctx, target)
	if err != nil {
		return "", err
	}

	bundle := Bundle{
		CertificateID:     cert.ID,
		CommonName:        cert.CommonName,
		SANs:              cert.SANs,
		SerialNumber:      cert.SerialNumber,
		FingerprintSHA256: cert.FingerprintSHA256,
		CertificatePEM:    *cert.CertificatePEM,
		Options:           binding.Options,
	}
	if cert.ChainPEM != nil {
		bundle.ChainPEM = *cert.ChainPEM
	}
	if cert.NotBefore != nil {
		bundle.NotBefore = *cert.NotBefore
	}
	if cert.NotAfter != nil {
		bundle.NotAfter = *cert.NotAfter
	}

	// Fetched only when the target says it cannot work without one, so an
	// ordinary deployment never causes a private key to be decrypted at all.
	if deployer.NeedsPrivateKey() {
		key, err := e.privateKey(ctx, cert)
		if err != nil {
			return "", err
		}
		bundle.PrivateKeyPEM = key
	}

	// Worth saying when it happens: this is the moment the certificate the job
	// was created for and the certificate being installed can differ, and the
	// second is deliberately the one that goes.
	if job.Fingerprint != "" && job.Fingerprint != cert.FingerprintSHA256 {
		slog.Info("deploying the certificate as it stands now, not the one this job was created for",
			"job", job.ID, "common_name", cert.CommonName,
			"enqueued_for", shortFingerprint(job.Fingerprint), "deploying", shortFingerprint(cert.FingerprintSHA256))
	}

	slog.Info("deploying certificate",
		"job", job.ID, "common_name", cert.CommonName,
		"target", target.Name, "target_type", target.TargetType, "where", deployer.Describe(),
		"carries_private_key", deployer.NeedsPrivateKey())

	attemptCtx, cancel := context.WithTimeout(ctx, deployTimeout)
	defer cancel()

	detail, err := deployer.Deploy(attemptCtx, bundle)
	now := time.Now()

	if err != nil {
		e.recordOutcome(ctx, binding, target, store.DeploymentOutcome{
			Status: store.DeploymentFailed,
			Error:  err.Error(),
			At:     now,
		})
		_ = e.store.CreateAuditLog(ctx, &store.AuditLog{
			Action:     "cert.deploy_failed",
			EntityType: "certificate",
			EntityID:   &cert.ID,
			Details: fmt.Sprintf(`{"cn": %q, "target": %q, "error": %q}`,
				cert.CommonName, target.Name, err.Error()),
		})
		return "", err
	}

	e.recordOutcome(ctx, binding, target, store.DeploymentOutcome{
		Status:      store.DeploymentDeployed,
		Fingerprint: cert.FingerprintSHA256,
		At:          now,
	})

	_ = e.store.CreateAuditLog(ctx, &store.AuditLog{
		Action:     "cert.deployed",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		Details: fmt.Sprintf(`{"cn": %q, "target": %q, "target_type": %q, "fingerprint": %q, "carried_private_key": %t}`,
			cert.CommonName, target.Name, target.TargetType, cert.FingerprintSHA256, deployer.NeedsPrivateKey()),
	})

	// Published as what it is. The certificate reached the target and the target
	// accepted it; whether the process in front of the users has picked it up is
	// a different question, answered by the verifier opening a connection.
	if e.broker != nil {
		e.broker.Publish(events.Event{
			Topic:    events.TopicCertDeployed,
			Severity: events.SeverityInfo,
			EntityID: cert.ID,
			Payload: map[string]any{
				"common_name": cert.CommonName,
				"target":      target.Name,
				"target_type": target.TargetType,
				"where":       deployer.Describe(),
				"fingerprint": cert.FingerprintSHA256,
				"detail":      detail,
			},
		})
	}

	// The other half of the loop. Deployment's success is a claim that bytes
	// were accepted; the verifier's is evidence from an actual handshake. Now
	// that CertPilot installs the certificate itself rather than waiting for a
	// person to, the check that proves it landed can be brought forward from
	// the half hour a renewal schedules — but only once every place this
	// certificate belongs is holding it, because a partial rollout verified
	// early is a STALE nobody needed to see.
	if Settled(ctx, e.store, cert.ID) {
		slog.Info("certificate deployed to every place it is bound",
			"common_name", cert.CommonName)
	}

	slog.Info("certificate deployed", "job", job.ID, "common_name", cert.CommonName,
		"target", target.Name, "detail", detail)
	return detail, nil
}

// recordOutcome writes what happened to the binding and to the target.
//
// Both, because they answer different questions. The binding says what this
// place is holding; the target says whether this place is working at all. A
// target failing for every certificate bound to it is a credential problem, and
// that is invisible if the only record is per certificate.
func (e *Executor) recordOutcome(ctx context.Context, binding *store.CertificateDeployment,
	target *store.DeploymentTarget, outcome store.DeploymentOutcome) {
	if err := e.store.RecordDeploymentOutcome(ctx, binding.ID, outcome); err != nil {
		slog.Error("a deployment finished but its record could not be updated",
			"deployment", binding.ID, "error", err)
	}
	if err := e.store.MarkDeploymentTargetUsed(ctx, target.ID, outcome.At,
		outcome.Status == store.DeploymentDeployed, outcome.Error); err != nil {
		slog.Error("a deployment finished but the target could not be updated",
			"target", target.ID, "error", err)
	}
}

// privateKey opens the sealed key for a certificate that is going somewhere
// that needs one.
//
// The error is phrased for whoever has to act on it, because the commonest
// cause is not a fault: a certificate that was discovered by a scan or imported
// from a cloud store has no key here, and never will until it is reissued
// through CertPilot.
func (e *Executor) privateKey(ctx context.Context, cert *store.Certificate) (string, error) {
	sealed, err := e.store.GetCertificatePrivateKey(ctx, cert.ID)
	if err != nil {
		return "", fmt.Errorf("could not read the private key for %s: %w", cert.CommonName, err)
	}
	if sealed == "" {
		return "", fmt.Errorf(
			"this target needs the private key and CertPilot does not hold one for %s. A certificate that was discovered or imported has no key here until it is reissued through CertPilot",
			cert.CommonName)
	}
	if !secrets.IsEnvelope(sealed) {
		// Written before encryption existed. Accepted rather than refused: the
		// alternative is declining to deploy a certificate that is working.
		return sealed, nil
	}
	plaintext, err := e.keyring.DecryptString(sealed, secrets.ContextCertificatePrivKey)
	if err != nil {
		return "", fmt.Errorf("could not decrypt the private key for %s: %w", cert.CommonName, err)
	}
	return plaintext, nil
}

// decryptConfig opens a target's sealed configuration.
func (e *Executor) decryptConfig(target *store.DeploymentTarget) (string, error) {
	if target.ConfigEncrypted == "" {
		return "", nil
	}
	if !secrets.IsEnvelope(target.ConfigEncrypted) {
		// Targets written before encryption existed are stored as plaintext.
		return target.ConfigEncrypted, nil
	}
	plaintext, err := e.keyring.DecryptString(target.ConfigEncrypted, secrets.ContextDeploymentConfig)
	if err != nil {
		return "", fmt.Errorf("could not decrypt the configuration for target %q: %w", target.Name, err)
	}
	return plaintext, nil
}

// buildDeployer opens a target's configuration and, for a cloud target, borrows
// the credentials of the connection it names.
//
// Cloud deployers do not store their own copy of an account's credentials.
// Two copies of one AWS key — one in cloud_connections for discovery, one in
// deployment_targets for deployment — is one rotation away from a system that
// can read an account it can no longer write to, and that surfaces at the worst
// possible moment.
//
// The connection's values win on a collision. A target may carry placement of
// its own, but it must never be able to override the credentials of the account
// somebody registered.
func (e *Executor) buildDeployer(ctx context.Context, target *store.DeploymentTarget) (Deployer, error) {
	raw, err := e.decryptConfig(target)
	if err != nil {
		return nil, err
	}

	config := map[string]any{}
	if strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), &config); err != nil {
			return nil, fmt.Errorf("the configuration for target %q is not valid JSON: %w", target.Name, err)
		}
	}

	if id := ConnectionID(config); id != "" {
		connection, err := e.store.GetCloudConnection(ctx, id)
		if err != nil {
			return nil, fmt.Errorf(
				"target %q borrows the credentials of a cloud connection that no longer exists: %w", target.Name, err)
		}
		if !connection.IsEnabled {
			// An error rather than a silent skip, for the reason a disabled
			// target is: somebody switched this off, and a queue that quietly
			// discards work because a switch is off is a queue that lies.
			return nil, fmt.Errorf(
				"the cloud connection %q that target %q uses is switched off", connection.Name, target.Name)
		}

		connectionConfig, err := e.openConnection(connection)
		if err != nil {
			return nil, err
		}
		config = MergeConnection(config, connectionConfig)
	}

	merged, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return Build(target.TargetType, string(merged))
}

// openConnection decrypts a cloud connection's stored credentials.
func (e *Executor) openConnection(connection *store.CloudConnection) (map[string]any, error) {
	out := map[string]any{}
	sealed := connection.ConfigEncrypted
	if sealed == "" {
		return out, nil
	}
	plaintext := sealed
	if secrets.IsEnvelope(sealed) {
		opened, err := e.keyring.DecryptString(sealed, secrets.ContextCloudConnectionConfig)
		if err != nil {
			return nil, fmt.Errorf(
				"could not decrypt the credentials for cloud connection %q: %w", connection.Name, err)
		}
		plaintext = opened
	}
	if err := json.Unmarshal([]byte(plaintext), &out); err != nil {
		return nil, fmt.Errorf(
			"the stored configuration for cloud connection %q is not valid JSON: %w", connection.Name, err)
	}
	return out, nil
}
