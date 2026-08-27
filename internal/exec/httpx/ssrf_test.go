package httpx

import (
	"net"
	"testing"
)

func TestIsMetadataBlocked(t *testing.T) {
	blocked := []string{
		"169.254.169.254", // AWS/GCP/Azure IMDS
		"169.254.170.2",   // ECS task metadata (still link-local)
		"fe80::1",
		"fd00:ec2::254", // AWS IPv6 metadata
	}
	for _, ip := range blocked {
		if !isMetadataBlocked(net.ParseIP(ip)) {
			t.Errorf("%s should be blocked", ip)
		}
	}

	allowed := []string{"10.20.4.11", "127.0.0.1", "8.8.8.8"}
	for _, ip := range allowed {
		if isMetadataBlocked(net.ParseIP(ip)) {
			t.Errorf("%s should not be blocked", ip)
		}
	}
}

func TestCidrContains(t *testing.T) {
	if !cidrContains("10.20.0.0/16", net.ParseIP("10.20.4.11")) {
		t.Error("10.20.4.11 should be in 10.20.0.0/16")
	}
	if cidrContains("10.20.0.0/16", net.ParseIP("10.21.4.11")) {
		t.Error("10.21.4.11 should not be in 10.20.0.0/16")
	}
	if cidrContains("not-a-cidr", net.ParseIP("10.20.4.11")) {
		t.Error("a malformed CIDR should never match")
	}
}
