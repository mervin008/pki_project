package cloudsync

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Kubernetes reads certificates out of `kubernetes.io/tls` secrets.
//
// This is where most internal TLS actually lives, and where the "nobody renews
// this" problem is at its worst. cert-manager renews the secrets it owns and
// nothing else. A secret created by hand — `kubectl create secret tls`, a Helm
// value, a copy-paste from a ticket — sits there looking identical to the ones
// cert-manager maintains, until the day it expires.
type Kubernetes struct {
	apiURL     string
	namespaces []string
	client     *http.Client
	// inCluster reads the credentials from the projected service account at
	// request time rather than at construction. Those tokens rotate — roughly
	// hourly on a modern cluster — and a connection that cached one at startup
	// stops working an hour later and reports it as an access problem.
	inCluster   bool
	staticToken string
}

const (
	serviceAccountDir   = "/var/run/secrets/kubernetes.io/serviceaccount"
	inClusterAPIDefault = "https://kubernetes.default.svc"
	tlsSecretType       = "kubernetes.io/tls"
)

func newKubernetes(config map[string]any) (*Kubernetes, error) {
	k := &Kubernetes{
		apiURL:      strings.TrimRight(configString(config, "api_url"), "/"),
		namespaces:  configStrings(config, "namespaces"),
		inCluster:   configBool(config, "in_cluster"),
		staticToken: configString(config, "token"),
	}

	if k.inCluster && k.apiURL == "" {
		k.apiURL = inClusterAPIDefault
	}
	if k.apiURL == "" {
		return nil, missingField("kubernetes", "api_url",
			"the cluster API server, e.g. https://10.0.0.1:6443 — or set in_cluster when CertPilot runs inside the cluster")
	}
	if !k.inCluster && k.staticToken == "" {
		return nil, missingField("kubernetes", "token",
			"a service account token with read access to secrets; grant it as narrowly as get/list on secrets and ingresses")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPEM := configString(config, "ca_cert"); caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, fmt.Errorf("the kubernetes ca_cert is not a PEM certificate")
		}
		tlsConfig.RootCAs = pool
	} else if k.inCluster {
		caPEM, err := os.ReadFile(serviceAccountDir + "/ca.crt")
		if err != nil {
			return nil, fmt.Errorf("in_cluster is set but the service account CA could not be read: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("the service account CA at %s/ca.crt is not a PEM certificate", serviceAccountDir)
		}
		tlsConfig.RootCAs = pool
	}
	if configBool(config, "insecure_skip_verify") {
		// Allowed, because a great many clusters are fronted by a certificate
		// from a CA CertPilot has no copy of, and refusing outright would mean
		// the secrets simply go unwatched. Recorded in the scope list so it is
		// visible on screen rather than only in a config nobody re-reads.
		tlsConfig.InsecureSkipVerify = true
	}

	client := defaultClient()
	client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	k.client = client
	return k, nil
}

// Type identifies the provider.
func (k *Kubernetes) Type() string { return "kubernetes" }

// Describe names the cluster.
func (k *Kubernetes) Describe() string { return k.apiURL }

// Scopes says what will be enumerated.
func (k *Kubernetes) Scopes() []string {
	where := "all namespaces"
	if len(k.namespaces) > 0 {
		where = "namespaces " + strings.Join(k.namespaces, ", ")
	}
	scopes := []string{
		fmt.Sprintf("secrets of type %s in %s", tlsSecretType, where),
		"ingresses (networking.k8s.io/v1), to see which secrets are actually in use",
	}
	if t, ok := k.client.Transport.(*http.Transport); ok && t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		scopes = append(scopes, "the cluster API certificate is not verified (insecure_skip_verify)")
	}
	return scopes
}

// Inventory lists every TLS secret, and which ingress uses it.
func (k *Kubernetes) Inventory(ctx context.Context) ([]Asset, error) {
	secrets, err := k.listSecrets(ctx)
	if err != nil {
		return nil, err
	}

	// Ingress references are what turn a list of secrets into a list of
	// secrets nothing is serving. A failure here is not fatal — the secrets
	// were read, and that is the bulk of the answer — but "attached" then stays
	// nil rather than false, because "no ingress uses this" and "we could not
	// find out" must not look the same.
	used, usedKnown := k.ingressReferences(ctx)

	assets := make([]Asset, 0, len(secrets))
	for _, secret := range secrets {
		pem, err := decodeSecretCertificate(secret)
		if err != nil {
			// Kept rather than dropped. A TLS secret whose tls.crt does not
			// decode is a broken secret somebody is relying on, which is worth
			// more attention than a working one, not less.
			pem = ""
		}

		resourceID := secret.Metadata.Namespace + "/" + secret.Metadata.Name
		asset := Asset{
			ResourceID:     resourceID,
			Name:           secret.Metadata.Name,
			Location:       secret.Metadata.Namespace,
			CertificatePEM: pem,
		}

		// cert-manager stamps the secrets it owns. Everything else in this list
		// is renewed by a person, if at all.
		if owner := certManagerOwner(secret.Metadata.Annotations); owner != "" {
			asset.RenewalMode = "cert-manager: " + owner
			yes := true
			asset.WillRenew = &yes
		} else {
			asset.RenewalMode = "manual"
			no := false
			asset.WillRenew = &no
		}

		if usedKnown {
			refs := used[resourceID]
			attached := len(refs) > 0
			asset.Attached = &attached
			asset.AttachedTo = refs
		}

		assets = append(assets, asset)
	}
	return assets, nil
}

// k8sSecret is the part of a Secret this needs.
type k8sSecret struct {
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Type string            `json:"type"`
	Data map[string]string `json:"data"`
}

type k8sSecretList struct {
	Items    []k8sSecret `json:"items"`
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
}

func (k *Kubernetes) listSecrets(ctx context.Context) ([]k8sSecret, error) {
	paths := []string{"/api/v1/secrets"}
	if len(k.namespaces) > 0 {
		paths = paths[:0]
		for _, ns := range k.namespaces {
			paths = append(paths, "/api/v1/namespaces/"+url.PathEscape(ns)+"/secrets")
		}
	}

	out := []k8sSecret{}
	for _, path := range paths {
		cont := ""
		for {
			query := url.Values{
				// Server-side, so a cluster with thousands of secrets does not
				// send all of them across the wire to have four kept.
				"fieldSelector": {"type=" + tlsSecretType},
				"limit":         {"500"},
			}
			if cont != "" {
				query.Set("continue", cont)
			}

			var page k8sSecretList
			if err := k.get(ctx, path+"?"+query.Encode(), &page); err != nil {
				return nil, err
			}
			out = append(out, page.Items...)

			cont = page.Metadata.Continue
			if cont == "" {
				break
			}
		}
	}
	return out, nil
}

type k8sIngressList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			TLS []struct {
				SecretName string   `json:"secretName"`
				Hosts      []string `json:"hosts"`
			} `json:"tls"`
		} `json:"spec"`
	} `json:"items"`
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
}

// ingressReferences maps namespace/secret to the ingresses using it.
//
// The bool is whether the question could be answered at all. Read access to
// ingresses is a separate RBAC grant from read access to secrets, and a
// deployment that has one without the other must report "unknown" rather than
// "nothing uses this".
func (k *Kubernetes) ingressReferences(ctx context.Context) (map[string][]string, bool) {
	paths := []string{"/apis/networking.k8s.io/v1/ingresses"}
	if len(k.namespaces) > 0 {
		paths = paths[:0]
		for _, ns := range k.namespaces {
			paths = append(paths, "/apis/networking.k8s.io/v1/namespaces/"+url.PathEscape(ns)+"/ingresses")
		}
	}

	refs := map[string][]string{}
	for _, path := range paths {
		cont := ""
		for {
			query := url.Values{"limit": {"500"}}
			if cont != "" {
				query.Set("continue", cont)
			}

			var page k8sIngressList
			if err := k.get(ctx, path+"?"+query.Encode(), &page); err != nil {
				return nil, false
			}
			for _, ing := range page.Items {
				for _, t := range ing.Spec.TLS {
					if t.SecretName == "" {
						continue
					}
					key := ing.Metadata.Namespace + "/" + t.SecretName
					refs[key] = append(refs[key], "ingress "+ing.Metadata.Namespace+"/"+ing.Metadata.Name)
				}
			}

			cont = page.Metadata.Continue
			if cont == "" {
				break
			}
		}
	}
	return refs, true
}

func (k *Kubernetes) get(ctx context.Context, path string, out any) error {
	token, err := k.token()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.apiURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	return doJSON(k.client, req, out)
}

// token returns the bearer token, re-read from disk each call when running in
// cluster because projected service account tokens rotate.
func (k *Kubernetes) token() (string, error) {
	if !k.inCluster {
		return k.staticToken, nil
	}
	raw, err := os.ReadFile(serviceAccountDir + "/token")
	if err != nil {
		return "", fmt.Errorf("in_cluster is set but the service account token could not be read: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// decodeSecretCertificate pulls the leaf certificate out of a TLS secret.
func decodeSecretCertificate(secret k8sSecret) (string, error) {
	raw, ok := secret.Data["tls.crt"]
	if !ok || raw == "" {
		return "", fmt.Errorf("secret %s/%s has no tls.crt", secret.Metadata.Namespace, secret.Metadata.Name)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("secret %s/%s has a tls.crt that is not base64: %w",
			secret.Metadata.Namespace, secret.Metadata.Name, err)
	}
	return string(decoded), nil
}

// certManagerOwner reports the cert-manager Certificate that owns this secret.
//
// Both annotation spellings are checked: the modern `cert-manager.io/` prefix
// and the pre-1.0 `certmanager.k8s.io/` one, which is still on secrets created
// years ago and never touched since — precisely the secrets this is looking for.
func certManagerOwner(annotations map[string]string) string {
	for _, key := range []string{
		"cert-manager.io/certificate-name",
		"certmanager.k8s.io/certificate-name",
	} {
		if v := strings.TrimSpace(annotations[key]); v != "" {
			return v
		}
	}
	return ""
}

// readableBody turns whatever a failing API returned into one line.
//
// Kubernetes returns a JSON Status object, the cloud providers return JSON or
// XML or an HTML error page. All of them are several lines, and pasting them
// into a dashboard field buries the one fact that matters — that the sync did
// not happen — under markup.
func readableBody(r io.Reader) string {
	raw, _ := io.ReadAll(io.LimitReader(r, 4096))
	body := string(raw)

	// A Kubernetes Status carries the sentence worth showing in "message".
	if idx := strings.Index(body, `"message"`); idx >= 0 {
		rest := body[idx+len(`"message"`):]
		if colon := strings.Index(rest, ":"); colon >= 0 {
			rest = strings.TrimSpace(rest[colon+1:])
			if strings.HasPrefix(rest, `"`) {
				if end := strings.Index(rest[1:], `"`); end >= 0 {
					return rest[1 : end+1]
				}
			}
		}
	}

	if strings.Contains(body, "<") {
		var out strings.Builder
		inTag := false
		for _, r := range body {
			switch {
			case r == '<':
				inTag = true
			case r == '>':
				inTag = false
				out.WriteRune(' ')
			case !inTag:
				out.WriteRune(r)
			}
		}
		body = out.String()
	}

	body = strings.Join(strings.Fields(body), " ")
	if body == "" {
		return "no detail given"
	}
	if len(body) > 200 {
		return body[:200] + "…"
	}
	return body
}
