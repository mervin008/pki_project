package discovery

import (
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultExpansionLimit caps how many endpoints one scan may expand to.
//
// The limit exists because expansion is where a typo becomes an incident. A
// misplaced digit turns 10.0.0.0/24 into 10.0.0.0/8 — sixteen million hosts,
// from CertPilot's address, on someone else's network. Refusing loudly at a
// number a human can reason about is the difference between a mistake and an
// outage report from a security team.
const DefaultExpansionLimit = 4096

// ExpandTargets turns what someone typed into the endpoints that will actually
// be connected to.
//
// Accepts, per entry:
//
//	example.com                a host
//	example.com:8443           a host on a port
//	10.0.0.0/24                every usable address in a network
//	10.0.0.0/24:8443           the same, on a port
//	10.0.0.10-10.0.0.40        an inclusive address range
//	10.0.0.10-40               the same, abbreviated in the last octet
//	[2001:db8::1]:8443         an IPv6 host
//	2001:db8::/120             an IPv6 network
//
// `ports` applies to every entry that does not name its own. Giving more than
// one multiplies the endpoint count, which is exactly why the total is capped.
//
// Expansion is all-or-nothing: one unparseable entry fails the whole call. A
// scan that quietly dropped an entry would report a clean range while never
// having looked at part of it, and nobody would know which part.
func ExpandTargets(specs []string, ports []int, limit int) ([]Target, error) {
	if limit <= 0 {
		limit = DefaultExpansionLimit
	}
	if len(ports) == 0 {
		ports = []int{DefaultPort}
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d is not a valid port", p)
		}
	}

	targets := make([]Target, 0, len(specs))
	seen := make(map[Target]bool, len(specs))

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

		hosts, specPorts, err := expandOne(spec, limit)
		if err != nil {
			return nil, err
		}
		if len(specPorts) == 0 {
			specPorts = ports
		}

		for _, host := range hosts {
			for _, port := range specPorts {
				t := Target{Host: host, Port: port}
				if seen[t] {
					continue
				}
				seen[t] = true
				targets = append(targets, t)
				if len(targets) > limit {
					return nil, fmt.Errorf(
						"that expands to more than %d endpoints; narrow the range or raise the limit deliberately", limit)
				}
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets to scan")
	}
	return targets, nil
}

// expandOne returns the hosts an entry names, and the ports it named itself.
func expandOne(spec string, limit int) ([]string, []int, error) {
	switch {
	case strings.Contains(spec, "/"):
		return expandCIDR(spec, limit)
	case isRange(spec):
		return expandRange(spec)
	default:
		target, err := ParseTarget(spec, 0)
		if err != nil {
			return nil, nil, err
		}
		// ParseTarget applies a default port; distinguish "named one" from
		// "took the default" so the request-level ports still apply.
		if hasExplicitPort(spec) {
			return []string{target.Host}, []int{target.Port}, nil
		}
		return []string{target.Host}, nil, nil
	}
}

// expandCIDR lists the usable addresses in a network.
func expandCIDR(spec string, limit int) ([]string, []int, error) {
	cidr, ports, err := splitTrailingPort(spec, strings.Index(spec, "/"))
	if err != nil {
		return nil, nil, err
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("%q is not a network in CIDR form: %w", cidr, err)
	}
	prefix = prefix.Masked()

	// Counted before anything is materialised. A /8 is sixteen million
	// addresses; building that list to then reject it is its own denial of
	// service, on the machine running CertPilot.
	size := new(big.Int).Lsh(big.NewInt(1), uint(prefix.Addr().BitLen()-prefix.Bits()))
	if size.Cmp(big.NewInt(int64(limit)+2)) > 0 {
		return nil, nil, fmt.Errorf(
			"%s covers %s addresses, past the %d-endpoint limit for one scan; narrow it",
			cidr, size.String(), limit)
	}

	// The network and broadcast addresses are not endpoints. Skipped for IPv4
	// prefixes wide enough to have them; /31 and /32 are point-to-point and a
	// single host respectively, where both addresses are real.
	skipEdges := prefix.Addr().Is4() && prefix.Bits() < 31

	hosts := make([]string, 0, size.Int64())
	addr := prefix.Addr()
	for prefix.Contains(addr) {
		hosts = append(hosts, addr.String())
		if !addr.Next().IsValid() {
			break
		}
		addr = addr.Next()
	}
	if skipEdges && len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}

	return hosts, ports, nil
}

// expandRange lists an inclusive address range.
func expandRange(spec string) ([]string, []int, error) {
	body, ports, err := splitTrailingPort(spec, 0)
	if err != nil {
		return nil, nil, err
	}

	dash := strings.Index(body, "-")
	startStr, endStr := body[:dash], body[dash+1:]

	start, err := netip.ParseAddr(startStr)
	if err != nil {
		return nil, nil, fmt.Errorf("%q is not an address range: %w", spec, err)
	}
	if !start.Is4() {
		return nil, nil, fmt.Errorf("%q: address ranges are IPv4 only; use CIDR form for IPv6", spec)
	}

	// The abbreviated form names only the final octet: 10.0.0.10-40.
	if !strings.Contains(endStr, ".") {
		octets := start.As4()
		last, convErr := strconv.Atoi(endStr)
		if convErr != nil || last < 0 || last > 255 {
			return nil, nil, fmt.Errorf("%q: %q is not a final octet", spec, endStr)
		}
		octets[3] = byte(last)
		endStr = netip.AddrFrom4(octets).String()
	}

	end, err := netip.ParseAddr(endStr)
	if err != nil {
		return nil, nil, fmt.Errorf("%q is not an address range: %w", spec, err)
	}
	if end.Less(start) {
		return nil, nil, fmt.Errorf("%q ends before it starts", spec)
	}

	hosts := []string{}
	for addr := start; ; addr = addr.Next() {
		hosts = append(hosts, addr.String())
		if addr == end || !addr.Next().IsValid() {
			break
		}
	}
	return hosts, ports, nil
}

// splitTrailingPort separates a ":port" suffix that appears after `from`.
//
// The offset matters: an IPv6 network is full of colons, and only the one after
// the prefix length can be a port.
func splitTrailingPort(spec string, from int) (string, []int, error) {
	idx := strings.LastIndex(spec[from:], ":")
	if idx < 0 {
		return spec, nil, nil
	}
	idx += from

	portStr := spec[idx+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", nil, fmt.Errorf("%q has an invalid port %q", spec, portStr)
	}
	return spec[:idx], []int{port}, nil
}

// isRange reports whether an entry is an address range rather than a host.
//
// Checks that what precedes the dash parses as an address, so a perfectly
// ordinary hostname like `web-01.corp` is not mistaken for one.
func isRange(spec string) bool {
	dash := strings.Index(spec, "-")
	if dash <= 0 {
		return false
	}
	body := spec
	if colon := strings.LastIndex(spec, ":"); colon > dash {
		body = spec[:colon]
	}
	dash = strings.Index(body, "-")
	if dash <= 0 {
		return false
	}
	_, err := netip.ParseAddr(body[:dash])
	return err == nil
}

// hasExplicitPort reports whether a host entry named its own port.
func hasExplicitPort(spec string) bool {
	if _, _, err := net.SplitHostPort(spec); err == nil {
		return true
	}
	return false
}
