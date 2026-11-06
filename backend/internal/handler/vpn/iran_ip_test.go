package vpn

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParseIranIPList(t *testing.T) {
	body := []byte(`# Iran
2.144.0.0/14
5.22.0.0/17
  5.22.5.0/24
185.1.2.3
10.202.10.10/31
192.168.1.0/24
100.64.1.0/24
2a01:5ec0::/29
not-an-ip
5.22.0.1/17
`)
	got := parseIranIPList(body)
	want := []netip.Prefix{
		netip.MustParsePrefix("2.144.0.0/14"),
		netip.MustParsePrefix("5.22.0.0/17"),
		netip.MustParsePrefix("5.22.5.0/24"),
		netip.MustParsePrefix("185.1.2.3/32"),
		netip.MustParsePrefix("5.22.0.0/17"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseIranIPList = %v\nwant %v", got, want)
	}
}

func TestMergePrefixes(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("5.22.5.0/24"),
		netip.MustParsePrefix("5.22.0.0/17"),
		netip.MustParsePrefix("2.144.0.0/14"),
		netip.MustParsePrefix("5.22.0.0/17"),
		netip.MustParsePrefix("5.23.0.0/16"),
	}
	got := mergePrefixes(in)
	want := []netip.Prefix{
		netip.MustParsePrefix("2.144.0.0/14"),
		netip.MustParsePrefix("5.22.0.0/17"),
		netip.MustParsePrefix("5.23.0.0/16"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergePrefixes = %v\nwant %v", got, want)
	}
}

func TestNormalizeListAddress(t *testing.T) {
	for in, want := range map[string]string{
		"5.22.0.0/17":     "5.22.0.0/17",
		"5.22.0.1/17":     "5.22.0.0/17",
		"185.1.2.3":       "185.1.2.3/32",
		"1.2.3.4-1.2.3.9": "1.2.3.4-1.2.3.9",
	} {
		if got := normalizeListAddress(in); got != want {
			t.Errorf("normalizeListAddress(%q) = %q, want %q", in, got, want)
		}
	}
}
