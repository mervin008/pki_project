package discovery

import (
	"strings"
	"testing"
)

func TestExpandTargets(t *testing.T) {
	cases := []struct {
		name  string
		specs []string
		ports []int
		want  []Target
	}{
		{
			name:  "a bare host takes the default port",
			specs: []string{"example.com"},
			want:  []Target{{"example.com", 443}},
		},
		{
			name:  "an explicit port wins over the request default",
			specs: []string{"example.com:8443"},
			ports: []int{443},
			want:  []Target{{"example.com", 8443}},
		},
		{
			name:  "several ports multiply each host",
			specs: []string{"a.test", "b.test"},
			ports: []int{443, 8443},
			want: []Target{
				{"a.test", 443}, {"a.test", 8443},
				{"b.test", 443}, {"b.test", 8443},
			},
		},
		{
			name:  "a /30 yields its two usable addresses",
			specs: []string{"10.0.0.0/30"},
			want:  []Target{{"10.0.0.1", 443}, {"10.0.0.2", 443}},
		},
		{
			// A /31 is point-to-point: both addresses are real endpoints, and
			// dropping them would silently skip half of every link in a range.
			name:  "a /31 keeps both addresses",
			specs: []string{"10.0.0.0/31"},
			want:  []Target{{"10.0.0.0", 443}, {"10.0.0.1", 443}},
		},
		{
			name:  "a /32 is one host",
			specs: []string{"10.0.0.7/32"},
			want:  []Target{{"10.0.0.7", 443}},
		},
		{
			name:  "a network can name its own port",
			specs: []string{"10.0.0.0/30:8443"},
			want:  []Target{{"10.0.0.1", 8443}, {"10.0.0.2", 8443}},
		},
		{
			name:  "an inclusive range",
			specs: []string{"10.0.0.4-10.0.0.6"},
			want:  []Target{{"10.0.0.4", 443}, {"10.0.0.5", 443}, {"10.0.0.6", 443}},
		},
		{
			name:  "a range abbreviated in the last octet",
			specs: []string{"10.0.0.4-6"},
			want:  []Target{{"10.0.0.4", 443}, {"10.0.0.5", 443}, {"10.0.0.6", 443}},
		},
		{
			name:  "a range with a port",
			specs: []string{"10.0.0.4-5:8443"},
			want:  []Target{{"10.0.0.4", 8443}, {"10.0.0.5", 8443}},
		},
		{
			name:  "an IPv6 network",
			specs: []string{"2001:db8::/126"},
			want: []Target{
				{"2001:db8::", 443}, {"2001:db8::1", 443},
				{"2001:db8::2", 443}, {"2001:db8::3", 443},
			},
		},
		{
			name:  "an IPv6 host with a port",
			specs: []string{"[2001:db8::1]:8443"},
			want:  []Target{{"2001:db8::1", 8443}},
		},
		{
			// A hostname with a dash in it is not an address range. Getting
			// this wrong would turn every `web-01.corp` into a parse error.
			name:  "a hostname containing a dash",
			specs: []string{"web-01.corp"},
			want:  []Target{{"web-01.corp", 443}},
		},
		{
			name:  "overlapping entries are scanned once",
			specs: []string{"10.0.0.0/30", "10.0.0.1", "10.0.0.2"},
			want:  []Target{{"10.0.0.1", 443}, {"10.0.0.2", 443}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExpandTargets(tc.specs, tc.ports, DefaultExpansionLimit)
			if err != nil {
				t.Fatalf("ExpandTargets(%v): %v", tc.specs, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d targets %v, want %d %v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("target %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// The guard that matters. A misplaced digit turns a /24 into a /8, and the
// consequence is sixteen million outbound connections carrying CertPilot's
// return address across somebody else's network.
func TestExpansionRefusesAnAbsurdRange(t *testing.T) {
	_, err := ExpandTargets([]string{"10.0.0.0/8"}, nil, DefaultExpansionLimit)
	if err == nil {
		t.Fatal("a /8 was accepted")
	}
	// The refusal has to name the size, so the reader can see the typo rather
	// than just being told no.
	if !strings.Contains(err.Error(), "16777216") {
		t.Errorf("the refusal does not say how large the range is: %v", err)
	}

	// And it must be refused without building the list first — a check that
	// materialises sixteen million strings to then reject them is its own
	// denial of service, on the machine running CertPilot.
	if _, err := ExpandTargets([]string{"::/0"}, nil, DefaultExpansionLimit); err == nil {
		t.Error("the whole IPv6 address space was accepted")
	}
}

func TestExpansionEnforcesTheEndpointLimit(t *testing.T) {
	// Within the CIDR check individually, past it once multiplied by ports.
	_, err := ExpandTargets([]string{"10.0.0.0/24"}, []int{443, 8443, 9443}, 500)
	if err == nil {
		t.Fatal("254 hosts on three ports were accepted against a 500 limit")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("the refusal does not name the limit: %v", err)
	}
}

// One unparseable entry fails the whole call. A scan that quietly dropped an
// entry would report a clean range while never having looked at part of it, and
// nobody would be able to say which part.
func TestExpansionIsAllOrNothing(t *testing.T) {
	cases := []string{
		"https://example.com",
		"10.0.0.0/nonsense",
		"10.0.0.9-10.0.0.1",
		"10.0.0.1:notaport",
		"2001:db8::1-2001:db8::4",
	}
	for _, bad := range cases {
		if _, err := ExpandTargets([]string{"good.test", bad}, nil, DefaultExpansionLimit); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}

	if _, err := ExpandTargets([]string{"example.com"}, []int{0}, DefaultExpansionLimit); err == nil {
		t.Error("port 0 was accepted")
	}
	if _, err := ExpandTargets(nil, nil, DefaultExpansionLimit); err == nil {
		t.Error("an empty target list was accepted")
	}
}

func TestExpandingAFullNetworkSkipsNetworkAndBroadcast(t *testing.T) {
	got, err := ExpandTargets([]string{"192.168.1.0/24"}, nil, DefaultExpansionLimit)
	if err != nil {
		t.Fatalf("ExpandTargets: %v", err)
	}
	if len(got) != 254 {
		t.Fatalf("got %d addresses, want 254", len(got))
	}
	if got[0].Host != "192.168.1.1" {
		t.Errorf("first address = %s, want 192.168.1.1 (the network address is not an endpoint)", got[0].Host)
	}
	if got[len(got)-1].Host != "192.168.1.254" {
		t.Errorf("last address = %s, want 192.168.1.254 (the broadcast address is not an endpoint)", got[len(got)-1].Host)
	}
}
