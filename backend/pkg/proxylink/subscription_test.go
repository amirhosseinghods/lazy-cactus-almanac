package proxylink

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	subVLESS  = "vless://bf000d23-0752-40b4-affe-68f7707a9661@a.example.com:443?security=tls#A"
	subTrojan = "trojan://pw@b.example.com:443#B"
)

func TestParseSubscriptionPlainList(t *testing.T) {
	body := strings.Join([]string{"# comment", subVLESS, "", "socks5://u@h:1", subTrojan, "garbage"}, "\r\n")
	res, err := ParseSubscription([]byte(body))
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(res.Links) != 2 || res.Skipped != 2 {
		t.Fatalf("links=%d skipped=%d, want 2 and 2", len(res.Links), res.Skipped)
	}
	if res.Links[0].Name != "A" || res.Links[1].Protocol != ProtocolTrojan {
		t.Fatalf("unexpected links: %+v %+v", res.Links[0], res.Links[1])
	}
}

func TestParseSubscriptionBase64(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(subVLESS + "\n" + subTrojan + "\n"))
	// Providers often wrap long base64 bodies across lines.
	wrapped := encoded[:20] + "\n" + encoded[20:]
	res, err := ParseSubscription([]byte(wrapped))
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(res.Links) != 2 || res.Skipped != 0 {
		t.Fatalf("links=%d skipped=%d, want 2 and 0", len(res.Links), res.Skipped)
	}
}

func TestParseSubscriptionSingBoxJSON(t *testing.T) {
	body := `{"outbounds":[
		{"type":"selector","tag":"select","outbounds":["de"]},
		{"type":"vless","tag":"de","server":"de.example.com","server_port":443,"uuid":"u","detour":"x"},
		{"type":"wireguard","tag":"wg","server":"w.example.com","server_port":51820},
		{"type":"direct","tag":"direct"}
	]}`
	res, err := ParseSubscription([]byte(body))
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(res.Links) != 1 || res.Skipped != 1 {
		t.Fatalf("links=%d skipped=%d, want 1 and 1", len(res.Links), res.Skipped)
	}
	out := res.Links[0].Outbound
	if res.Links[0].Name != "de" || out["uuid"] != "u" {
		t.Fatalf("unexpected link: %+v", res.Links[0])
	}
	if _, ok := out["detour"]; ok {
		t.Fatal("detour must be stripped from reused outbounds")
	}
	if _, ok := out["tag"]; ok {
		t.Fatal("tag must be stripped from reused outbounds")
	}
}

func TestParseSubscriptionTruncates(t *testing.T) {
	var lines []string
	for i := 0; i < MaxSubscriptionLinks+5; i++ {
		lines = append(lines, fmt.Sprintf("trojan://pw@s%d.example.com:443", i))
	}
	res, err := ParseSubscription([]byte(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(res.Links) != MaxSubscriptionLinks || res.Truncated != 5 {
		t.Fatalf("links=%d truncated=%d", len(res.Links), res.Truncated)
	}
}

func TestParseSubscriptionErrors(t *testing.T) {
	for _, body := range []string{"", "   ", "not base64 !!!", "socks5://u@h:1\nhttp://x", `{"outbounds":[{"type":"direct"}]}`, `{bad json`} {
		if _, err := ParseSubscription([]byte(body)); err == nil {
			t.Errorf("ParseSubscription(%q) succeeded, want error", body)
		}
	}
}

func TestGatewayConfigURLTest(t *testing.T) {
	a, _ := Parse(subVLESS)
	b, _ := Parse(subTrojan)
	raw, err := GatewayConfig([]*Link{a, b}, GatewayOptions{ClashAPISecret: "s3cret"})
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	var cfg struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
		} `json:"dns"`
		Outbounds    []map[string]any `json:"outbounds"`
		Route        map[string]any   `json:"route"`
		Experimental struct {
			ClashAPI map[string]any `json:"clash_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	group := cfg.Outbounds[0]
	if group["type"] != "urltest" || group["tag"] != ProxyTag {
		t.Fatalf("first outbound = %v, want the urltest group", group)
	}
	members, _ := group["outbounds"].([]any)
	if len(members) != 2 || members[0] != "server-1" || members[1] != "server-2" {
		t.Fatalf("urltest members = %v", members)
	}
	if cfg.Outbounds[1]["tag"] != "server-1" || cfg.Outbounds[2]["tag"] != "server-2" || cfg.Outbounds[3]["type"] != "direct" {
		t.Fatalf("unexpected outbounds: %v", cfg.Outbounds)
	}
	if cfg.Route["final"] != ProxyTag {
		t.Fatalf("route.final = %v", cfg.Route["final"])
	}
	if cfg.DNS.Servers[0]["detour"] != ProxyTag {
		t.Fatalf("remote DNS must go through the proxy group: %v", cfg.DNS.Servers[0])
	}
	if cfg.Experimental.ClashAPI["secret"] != "s3cret" {
		t.Fatalf("clash api = %v", cfg.Experimental.ClashAPI)
	}

	// The only direct route must be private ranges; IPv6 must be rejected.
	var sawIPv6Reject bool
	for _, r := range cfg.Route["rules"].([]any) {
		rule := r.(map[string]any)
		if rule["outbound"] == "direct" && rule["ip_is_private"] != true {
			t.Fatalf("unexpected direct rule: %v", rule)
		}
		if rule["ip_version"] == float64(6) && rule["action"] == "reject" {
			sawIPv6Reject = true
		}
	}
	if !sawIPv6Reject {
		t.Fatal("IPv6 must be rejected")
	}
}

func TestGatewayConfigNoLinks(t *testing.T) {
	if _, err := GatewayConfig(nil, GatewayOptions{}); err == nil {
		t.Fatal("GatewayConfig(nil) succeeded, want error")
	}
}
