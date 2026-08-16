package solver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const cloudflareAPI = "https://api.cloudflare.com/client/v4"

// Cloudflare solves dns-01 challenges by writing TXT records through the
// Cloudflare API.
//
// The token needs Zone:Read and DNS:Edit on the zones you intend to validate.
// Zone lookup walks up the domain labels, so a challenge for
// "a.b.example.com" finds the "example.com" zone without being told about it.
type Cloudflare struct {
	apiToken   string
	httpClient *http.Client

	mu        sync.Mutex
	zoneCache map[string]string // zone name -> zone id
	// recordIDs maps FQDN + value to the created record, so CleanUp deletes
	// exactly the record it created. Keying on value as well as name matters:
	// a wildcard order produces two TXT records at the same FQDN.
	recordIDs map[string]string
}

// NewCloudflare builds a Cloudflare DNS-01 solver.
func NewCloudflare(apiToken string) (*Cloudflare, error) {
	if strings.TrimSpace(apiToken) == "" {
		return nil, fmt.Errorf("cloudflare: api_token is required")
	}
	return &Cloudflare{
		apiToken:   apiToken,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		zoneCache:  make(map[string]string),
		recordIDs:  make(map[string]string),
	}, nil
}

// Type implements Solver.
func (c *Cloudflare) Type() string { return TypeDNS01 }

// Present creates the challenge TXT record.
func (c *Cloudflare) Present(ctx context.Context, ch Challenge) error {
	fqdn := ch.FQDN()

	zoneID, err := c.findZoneID(ctx, ch.Domain)
	if err != nil {
		return err
	}

	body := map[string]any{
		"type":    "TXT",
		"name":    fqdn,
		"content": ch.Value,
		"ttl":     60,
		"comment": "CertPilot ACME dns-01 challenge",
	}

	var resp struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", body, &resp); err != nil {
		return fmt.Errorf("cloudflare: failed to create TXT record for %s: %w", fqdn, err)
	}

	c.mu.Lock()
	c.recordIDs[recordKey(fqdn, ch.Value)] = zoneID + "/" + resp.Result.ID
	c.mu.Unlock()

	slog.Debug("cloudflare TXT record created", "fqdn", fqdn, "record_id", resp.Result.ID)
	return nil
}

// CleanUp deletes the challenge TXT record.
func (c *Cloudflare) CleanUp(ctx context.Context, ch Challenge) error {
	fqdn := ch.FQDN()
	key := recordKey(fqdn, ch.Value)

	c.mu.Lock()
	ref, ok := c.recordIDs[key]
	delete(c.recordIDs, key)
	c.mu.Unlock()

	if !ok {
		return nil
	}

	zoneID, recordID, found := strings.Cut(ref, "/")
	if !found {
		return nil
	}

	if err := c.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+recordID, nil, nil); err != nil {
		return fmt.Errorf("cloudflare: failed to delete TXT record %s: %w", fqdn, err)
	}

	slog.Debug("cloudflare TXT record deleted", "fqdn", fqdn, "record_id", recordID)
	return nil
}

// findZoneID walks up the domain labels until Cloudflare recognises a zone, so
// deeply nested subdomains resolve to the right zone.
func (c *Cloudflare) findZoneID(ctx context.Context, domain string) (string, error) {
	domain = strings.TrimSuffix(domain, ".")
	labels := strings.Split(domain, ".")

	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")

		c.mu.Lock()
		cached, ok := c.zoneCache[candidate]
		c.mu.Unlock()
		if ok {
			return cached, nil
		}

		var resp struct {
			Result []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		path := "/zones?name=" + url.QueryEscape(candidate)
		if err := c.do(ctx, http.MethodGet, path, nil, &resp); err != nil {
			return "", fmt.Errorf("cloudflare: zone lookup failed for %s: %w", candidate, err)
		}

		if len(resp.Result) > 0 {
			id := resp.Result[0].ID
			c.mu.Lock()
			c.zoneCache[candidate] = id
			c.mu.Unlock()
			return id, nil
		}
	}

	return "", fmt.Errorf("cloudflare: no zone found for %s — check the API token has Zone:Read on it", domain)
}

func (c *Cloudflare) do(ctx context.Context, method, path string, body any, out any) error {
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, cloudflareAPI+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Cloudflare reports failures in the body as well as the status code, and
	// the body carries the actionable message.
	var envelope struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	raw := new(bytes.Buffer)
	if _, err := raw.ReadFrom(resp.Body); err != nil {
		return err
	}

	if err := json.Unmarshal(raw.Bytes(), &envelope); err == nil && !envelope.Success {
		if len(envelope.Errors) > 0 {
			e := envelope.Errors[0]
			return fmt.Errorf("api error %d: %s", e.Code, e.Message)
		}
		return fmt.Errorf("api request failed with status %d", resp.StatusCode)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("api returned status %d", resp.StatusCode)
	}

	if out != nil {
		if err := json.Unmarshal(raw.Bytes(), out); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}
	return nil
}

func recordKey(fqdn, value string) string { return fqdn + "\x00" + value }
