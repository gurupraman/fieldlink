// Package httpx implements the http.request capability (design.md §5) as
// the call_internal_http MCP tool. SSRF is the primary threat here
// (design.md §6.5), so DNS is resolved once, the resolved IP is checked
// against the grant's CIDR allow-list and a hard-coded metadata block, and
// the connection is dialed to that specific IP — not re-resolved by the
// HTTP client later, which is exactly the gap a DNS-rebinding attack needs.
package httpx

import (
	"fmt"
	"net"
)

// metadataBlocks are cloud instance-metadata endpoints that are refused
// regardless of what any grant permits (design.md §5.1, §6.5). Rather than
// hard-coding only the two addresses design.md names, this blocks the
// link-local range those addresses live in (169.254.0.0/16, fe80::/10) —
// every major cloud's metadata service uses link-local space, so this is a
// strict superset of the letter of the spec, not a narrower reading of it.
var metadataBlocks = mustParseCIDRs(
	"169.254.0.0/16", // covers 169.254.169.254 (AWS/GCP/Azure IMDS)
	"fe80::/10",
	"fd00:ec2::254/128", // AWS IPv6 metadata endpoint (not link-local)
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		nets = append(nets, n)
	}
	return nets
}

// isMetadataBlocked reports whether ip is a cloud metadata endpoint that
// must never be reachable, no matter what a grant says.
func isMetadataBlocked(ip net.IP) bool {
	for _, n := range metadataBlocks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// resolve looks up host and returns its IPs. It does not decide policy —
// callers check the result against the grant and the metadata block.
func resolve(host string) ([]net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", host)
	}
	return ips, nil
}

// cidrContains reports whether ip falls within cidr (a string like
// "10.20.0.0/16"). A malformed cidr never matches.
func cidrContains(cidr string, ip net.IP) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return n.Contains(ip)
}
