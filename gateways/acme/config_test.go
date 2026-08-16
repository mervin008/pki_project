package acme

import (
	"strings"
	"testing"

	"github.com/certpilot/certpilot/gateways/acme/solver"
)

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig("", LetsEncryptStaging, ":80")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	if cfg.DirectoryURL != LetsEncryptStaging {
		t.Errorf("directory = %q, want the supplied default", cfg.DirectoryURL)
	}
	if cfg.Challenge != solver.TypeHTTP01 {
		t.Errorf("challenge = %q, want http-01 when no DNS provider is configured", cfg.Challenge)
	}
}

func TestParseConfigResolvesAliases(t *testing.T) {
	cases := map[string]string{
		"letsencrypt":         LetsEncryptProduction,
		"letsencrypt-staging": LetsEncryptStaging,
		"zerossl":             ZeroSSLProduction,
		"buypass":             BuypassProduction,
		"google":              GoogleTrustServices,
	}

	for alias, want := range cases {
		t.Run(alias, func(t *testing.T) {
			cfg, err := ParseConfig(`{"directory_url":"`+alias+`"}`, "", "")
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}
			if cfg.DirectoryURL != want {
				t.Fatalf("directory = %q, want %q", cfg.DirectoryURL, want)
			}
		})
	}
}

func TestParseConfigDefaultsToDNS01WhenProviderIsSet(t *testing.T) {
	cfg, err := ParseConfig(`{"dns_provider":"cloudflare","dns_config":{"api_token":"t"}}`, LetsEncryptStaging, ":80")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Challenge != solver.TypeDNS01 {
		t.Fatalf("challenge = %q, want dns-01 when a DNS provider is configured", cfg.Challenge)
	}
}

func TestParseConfigRejectsBadJSON(t *testing.T) {
	if _, err := ParseConfig(`{"directory_url":`, "", ""); err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantErr     bool
		errContains string
	}{
		{
			name: "valid http-01",
			raw:  `{"email":"ops@example.com","challenge":"http-01"}`,
		},
		{
			name: "valid cloudflare dns-01",
			raw:  `{"email":"ops@example.com","challenge":"dns-01","dns_provider":"cloudflare","dns_config":{"api_token":"secret"}}`,
		},
		{
			name: "valid webhook dns-01",
			raw:  `{"email":"ops@example.com","challenge":"dns-01","dns_provider":"webhook","dns_config":{"url":"https://dns.example.com/acme","bearer_token":"t"}}`,
		},
		{
			name:        "dns-01 without a provider",
			raw:         `{"email":"ops@example.com","challenge":"dns-01"}`,
			wantErr:     true,
			errContains: "dns_provider is required",
		},
		{
			name:        "cloudflare without a token",
			raw:         `{"email":"ops@example.com","challenge":"dns-01","dns_provider":"cloudflare"}`,
			wantErr:     true,
			errContains: "api_token",
		},
		{
			name:        "webhook without a URL",
			raw:         `{"email":"ops@example.com","challenge":"dns-01","dns_provider":"webhook"}`,
			wantErr:     true,
			errContains: "url is required",
		},
		{
			name:        "unknown DNS provider",
			raw:         `{"email":"ops@example.com","challenge":"dns-01","dns_provider":"bind9"}`,
			wantErr:     true,
			errContains: "unsupported dns_provider",
		},
		{
			name:        "unknown challenge",
			raw:         `{"email":"ops@example.com","challenge":"tls-alpn-01"}`,
			wantErr:     true,
			errContains: "unsupported challenge",
		},
		{
			name:        "half-configured EAB",
			raw:         `{"email":"ops@example.com","challenge":"http-01","eab_key_id":"kid"}`,
			wantErr:     true,
			errContains: "must be supplied together",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfig(tc.raw, LetsEncryptStaging, ":80")
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}

			errs, _ := cfg.Validate()
			if tc.wantErr {
				if len(errs) == 0 {
					t.Fatal("expected a validation error")
				}
				if tc.errContains != "" && !strings.Contains(strings.Join(errs, "; "), tc.errContains) {
					t.Fatalf("errors %v do not mention %q", errs, tc.errContains)
				}
				return
			}
			if len(errs) > 0 {
				t.Fatalf("unexpected validation errors: %v", errs)
			}
		})
	}
}

// ZeroSSL and Google Trust Services require External Account Binding. Saying so
// at configuration time is far better than a confusing rejection at issuance.
func TestValidateRequiresEABForKnownCAs(t *testing.T) {
	for _, directory := range []string{ZeroSSLProduction, GoogleTrustServices} {
		t.Run(directory, func(t *testing.T) {
			cfg, err := ParseConfig(`{"email":"ops@example.com","challenge":"http-01","directory_url":"`+directory+`"}`, "", ":80")
			if err != nil {
				t.Fatalf("ParseConfig: %v", err)
			}

			errs, _ := cfg.Validate()
			if len(errs) == 0 {
				t.Fatal("expected an EAB requirement error")
			}
			if !strings.Contains(strings.Join(errs, "; "), "External Account Binding") {
				t.Fatalf("errors %v should mention External Account Binding", errs)
			}
		})
	}
}

func TestValidateWarnsOnMissingEmail(t *testing.T) {
	cfg, err := ParseConfig(`{"challenge":"http-01"}`, LetsEncryptStaging, ":80")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	_, warnings := cfg.Validate()
	if len(warnings) == 0 {
		t.Fatal("expected a warning about the missing contact address")
	}
}

func TestValidateWarnsOnUnverifiableWebhook(t *testing.T) {
	cfg, err := ParseConfig(
		`{"email":"ops@example.com","challenge":"dns-01","dns_provider":"webhook","dns_config":{"url":"https://dns.example.com"}}`,
		LetsEncryptStaging, ":80")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	errs, warnings := cfg.Validate()
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(warnings) == 0 {
		t.Fatal("a webhook with neither a bearer token nor a signing secret should warn")
	}
}

func TestBuildSolvers(t *testing.T) {
	t.Run("http-01 binds a listener", func(t *testing.T) {
		cfg, err := ParseConfig(`{"challenge":"http-01","http01_bind_addr":"127.0.0.1:0"}`, LetsEncryptStaging, "")
		if err != nil {
			t.Fatalf("ParseConfig: %v", err)
		}

		set, err := cfg.BuildSolvers()
		if err != nil {
			t.Fatalf("BuildSolvers: %v", err)
		}
		defer set.Close()

		if _, ok := set.For(solver.TypeHTTP01); !ok {
			t.Fatal("expected an http-01 solver")
		}
	})

	t.Run("cloudflare", func(t *testing.T) {
		cfg, err := ParseConfig(`{"challenge":"dns-01","dns_provider":"cloudflare","dns_config":{"api_token":"t"}}`, LetsEncryptStaging, "")
		if err != nil {
			t.Fatalf("ParseConfig: %v", err)
		}

		set, err := cfg.BuildSolvers()
		if err != nil {
			t.Fatalf("BuildSolvers: %v", err)
		}
		defer set.Close()

		if _, ok := set.For(solver.TypeDNS01); !ok {
			t.Fatal("expected a dns-01 solver")
		}
	})

	t.Run("unsupported provider", func(t *testing.T) {
		cfg, err := ParseConfig(`{"challenge":"dns-01","dns_provider":"nsupdate"}`, LetsEncryptStaging, "")
		if err != nil {
			t.Fatalf("ParseConfig: %v", err)
		}
		if _, err := cfg.BuildSolvers(); err == nil {
			t.Fatal("expected an error for an unsupported provider")
		}
	})
}

func TestTimeouts(t *testing.T) {
	cfg, err := ParseConfig(`{"order_timeout_seconds":1200,"propagation_min_wait_seconds":45,"propagation_timeout_seconds":300}`, LetsEncryptStaging, "")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	if got := cfg.OrderTimeout().Seconds(); got != 1200 {
		t.Errorf("OrderTimeout = %v, want 1200s", got)
	}
	prop := cfg.Propagation()
	if prop.MinWait.Seconds() != 45 {
		t.Errorf("MinWait = %v, want 45s", prop.MinWait)
	}
	if prop.Timeout.Seconds() != 300 {
		t.Errorf("Timeout = %v, want 300s", prop.Timeout)
	}

	// Unset values fall back to defaults rather than zero, which would mean
	// "no timeout" and hang a renewal forever.
	bare, _ := ParseConfig("", LetsEncryptStaging, "")
	if bare.OrderTimeout() <= 0 {
		t.Error("OrderTimeout must have a non-zero default")
	}
	if bare.Propagation().Timeout <= 0 {
		t.Error("propagation timeout must have a non-zero default")
	}
}

func TestDecodeEABKey(t *testing.T) {
	// CAs hand these out in several encodings; all must work.
	for _, encoded := range []string{
		"aGVsbG8td29ybGQ",  // raw base64url
		"aGVsbG8td29ybGQ=", // padded
		"aGVsbG8td29ybGQ=", // standard
	} {
		got, err := decodeEABKey(encoded)
		if err != nil {
			t.Fatalf("decodeEABKey(%q): %v", encoded, err)
		}
		if string(got) != "hello-world" {
			t.Fatalf("decodeEABKey(%q) = %q", encoded, got)
		}
	}
}
