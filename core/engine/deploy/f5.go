package deploy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// F5 BIG-IP, over iControl REST.
//
// The odd one out in this package: not a cloud API but an appliance, usually on
// a management address reachable from nowhere on the internet, very often
// presenting a certificate it issued itself. All three of those shape what
// follows.
//
// The sequence is four calls and the last one is the one that matters:
//
//  1. Exchange the credentials for a token, because iControl's basic auth on
//     every request means the password crosses the wire on every request.
//  2. Upload the certificate and the key to the appliance's file store.
//  3. Install each into the crypto store **under the name that is already
//     there**, which replaces it in place.
//  4. Nothing. Step 3 is the deployment — precisely because the name was
//     already there.
//
// A certificate installed under a *new* name sits in the crypto store while the
// client-SSL profile on the virtual server carries on referencing the old one.
// The appliance reports success, the certificate appears in the list, and the
// virtual server expires on schedule. This is ACM's missing-ARN mistake in
// F5's vocabulary, and it is why the profile is not modified here: pointing an
// existing profile at a *different* certificate is a change to what a virtual
// server serves, and it belongs to whoever owns that virtual server. Replacing
// the material behind the name they already chose does not.
type f5Deployer struct {
	host     string
	username string
	password string
	client   *http.Client
	insecure bool
}

const (
	// f5UploadChunk bounds one upload request. iControl accepts a file in
	// Content-Range chunks; certificates are small enough that one chunk is
	// always enough, and the constant exists so that stops being an accident.
	f5UploadChunk = 1 << 20
	// f5DownloadDir is where iControl puts uploaded files. Fixed by the
	// appliance, not a choice.
	f5DownloadDir = "/var/config/rest/downloads"
)

func newF5Deployer(config map[string]any) (Deployer, error) {
	host := strings.TrimRight(configString(config, "host"), "/")
	if host == "" {
		return nil, missingField(TypeF5, "host",
			"the management address, e.g. https://bigip.internal — not the virtual server's address")
	}
	if !strings.HasPrefix(host, "http") {
		host = "https://" + host
	}
	if strings.HasPrefix(host, "http://") {
		return nil, fmt.Errorf(
			"an F5 management address must be https; the certificate and its private key travel over this connection")
	}

	f := &f5Deployer{
		host:     host,
		username: configString(config, "username"),
		password: configString(config, "password"),
		insecure: configBool(config, "insecure_skip_verify"),
	}
	if f.username == "" || f.password == "" {
		return nil, missingField(TypeF5, "username and password",
			"an account with permission to install certificates and to write the crypto store")
	}

	transport := &http.Transport{}
	if f.insecure {
		// Allowed, named, and stored so it is answerable with a SELECT. A BIG-IP
		// management interface very often presents a certificate its own admin
		// generated, and refusing outright would mean the honest answer is to
		// not use this deployer at all — which gets a certificate copied about
		// by hand instead. The tradeoff is real and belongs to the operator,
		// but it must not be invisible.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	f.client = &http.Client{Timeout: 45 * time.Second, Transport: transport}
	return f, nil
}

func (f *f5Deployer) Type() string { return TypeF5 }

func (f *f5Deployer) Describe() string {
	if f.insecure {
		return f.host + " (TLS verification off)"
	}
	return f.host
}

// NeedsPrivateKey is true. A BIG-IP terminates TLS, so it holds the key.
func (f *f5Deployer) NeedsPrivateKey() bool { return true }

func (f *f5Deployer) Deploy(ctx context.Context, b Bundle) (string, error) {
	name := optionString(b.Options, "name")
	if name == "" {
		return "", fmt.Errorf(
			"this deployment has no name, and installing under a new one would leave the client-SSL profile on the virtual server pointing at the previous certificate")
	}
	partition := optionString(b.Options, "partition")
	if partition == "" {
		partition = "Common"
	}

	token, err := f.login(ctx)
	if err != nil {
		return "", err
	}

	certFile := name + ".crt"
	keyFile := name + ".key"

	body := b.CertificatePEM
	if strings.TrimSpace(b.ChainPEM) != "" {
		// The chain goes in the certificate file. A BIG-IP serves what is in
		// the cert object, and a leaf without its intermediates is a handshake
		// that works in a browser with a cached intermediate and fails in
		// everything else — the classic F5 misconfiguration.
		if !strings.HasSuffix(body, "\n") {
			body += "\n"
		}
		body += b.ChainPEM
	}

	if err := f.upload(ctx, token, certFile, []byte(body)); err != nil {
		return "", fmt.Errorf("could not upload the certificate: %w", err)
	}
	if err := f.upload(ctx, token, keyFile, []byte(b.PrivateKeyPEM)); err != nil {
		return "", fmt.Errorf("could not upload the private key: %w", err)
	}

	// The key first. If the certificate landed and the key did not, the
	// appliance holds a pair that does not match and the next reload of that
	// profile fails; the other order leaves a key nothing references, which is
	// inert.
	if err := f.install(ctx, token, "key", name, keyFile, partition); err != nil {
		return "", fmt.Errorf("could not install the private key on %s: %w", f.host, err)
	}
	if err := f.install(ctx, token, "cert", name, certFile, partition); err != nil {
		return "", fmt.Errorf("could not install the certificate on %s: %w", f.host, err)
	}

	return fmt.Sprintf(
		"installed %s as /%s/%s on %s, replacing the material behind the name the client-SSL profile already references",
		b.CommonName, partition, name, f.host), nil
}

// login exchanges the credentials for a token.
func (f *f5Deployer) login(ctx context.Context) (string, error) {
	payload, _ := json.Marshal(map[string]any{
		"username":          f.username,
		"password":          f.password,
		"loginProviderName": "tmos",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.host+"/mgmt/shared/authn/login", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	var resp struct {
		Token struct {
			Token string `json:"token"`
		} `json:"token"`
	}
	if err := f.do(ctx, req, &resp); err != nil {
		return "", fmt.Errorf("could not authenticate to %s: %w", f.host, err)
	}
	if resp.Token.Token == "" {
		return "", fmt.Errorf("%s accepted the credentials and returned no token", f.host)
	}
	return resp.Token.Token, nil
}

// upload sends one file to the appliance's transfer area.
func (f *f5Deployer) upload(ctx context.Context, token, filename string, body []byte) error {
	if len(body) == 0 {
		return fmt.Errorf("%s is empty", filename)
	}
	if len(body) > f5UploadChunk {
		// Chunking is possible and deliberately not implemented: a certificate
		// or key over a megabyte is not a certificate, and silently splitting
		// one would mean writing a resumption path that nothing here can ever
		// exercise.
		return fmt.Errorf("%s is %d bytes, which is not a certificate or a key", filename, len(body))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.host+"/mgmt/shared/file-transfer/uploads/"+url.PathEscape(filename), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Range", fmt.Sprintf("0-%d/%d", len(body)-1, len(body)))
	req.Header.Set("X-F5-Auth-Token", token)
	return f.do(ctx, req, nil)
}

// install moves an uploaded file into the crypto store under a given name.
//
// `command: install` over an existing name replaces it, which is the entire
// point: everything already referencing that name follows.
func (f *f5Deployer) install(ctx context.Context, token, kind, name, filename, partition string) error {
	payload, _ := json.Marshal(map[string]any{
		"command":         "install",
		"name":            name,
		"from-local-file": f5DownloadDir + "/" + filename,
		"partition":       partition,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.host+"/mgmt/tm/sys/crypto/"+kind, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-F5-Auth-Token", token)
	return f.do(ctx, req, nil)
}

// do performs one request and turns iControl's error shape into a sentence.
func (f *f5Deployer) do(ctx context.Context, req *http.Request, out any) error {
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// iControl puts the useful part in `message`, and the status line on
		// its own says almost nothing.
		var apiErr struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &apiErr) == nil && apiErr.Message != "" {
			return fmt.Errorf("%s returned %d: %s", req.URL.Path, resp.StatusCode, apiErr.Message)
		}
		return fmt.Errorf("%s returned %d: %s", req.URL.Path, resp.StatusCode,
			strings.Join(strings.Fields(string(raw)), " "))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}
