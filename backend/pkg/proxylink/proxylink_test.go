package proxylink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestParseVLESSReality(t *testing.T) {
	link, err := Parse("vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443" +
		"?security=reality&sni=www.microsoft.com&fp=firefox&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0" +
		"&sid=0123abcd&flow=xtls-rprx-vision&type=tcp#My%20Server")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if link.Protocol != ProtocolVLESS || link.Name != "My Server" || link.Server != "example.com" || link.Port != 443 {
		t.Fatalf("unexpected link header: %+v", link)
	}
	want := map[string]any{
		"type":            "vless",
		"server":          "example.com",
		"server_port":     443,
		"uuid":            "bf000d23-0752-40b4-affe-68f7707a9661",
		"flow":            "xtls-rprx-vision",
		"packet_encoding": "xudp",
		"tls": map[string]any{
			"enabled":     true,
			"server_name": "www.microsoft.com",
			"utls":        map[string]any{"enabled": true, "fingerprint": "firefox"},
			"reality": map[string]any{
				"enabled":    true,
				"public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
				"short_id":   "0123abcd",
			},
		},
	}
	assertOutbound(t, link.Outbound, want)
}

func TestParseVLESSWebSocketTLS(t *testing.T) {
	link, err := Parse("vless://uuid-1@1.2.3.4:8443?security=tls&type=ws&host=cdn.example.com" +
		"&path=%2Fws%3Fed%3D2048&alpn=h2,http/1.1&allowInsecure=1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string]any{
		"type":            "vless",
		"server":          "1.2.3.4",
		"server_port":     8443,
		"uuid":            "uuid-1",
		"packet_encoding": "xudp",
		"tls": map[string]any{
			"enabled":     true,
			"server_name": "cdn.example.com",
			"insecure":    true,
			"alpn":        []string{"h2", "http/1.1"},
		},
		"transport": map[string]any{
			"type":                   "ws",
			"path":                   "/ws",
			"headers":                map[string]any{"Host": "cdn.example.com"},
			"max_early_data":         2048,
			"early_data_header_name": "Sec-WebSocket-Protocol",
		},
	}
	assertOutbound(t, link.Outbound, want)
}

func TestParseVLESSPlainGRPC(t *testing.T) {
	link, err := Parse("vless://id@host.example:80?type=grpc&serviceName=svc&security=none")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := link.Outbound["tls"]; ok {
		t.Fatalf("plain link must not enable TLS: %v", link.Outbound)
	}
	assertOutbound(t, link.Outbound["transport"].(map[string]any), map[string]any{"type": "grpc", "service_name": "svc"})
}

func TestParseVMess(t *testing.T) {
	body := `{"v":"2","ps":"Germany","add":"de.example.com","port":"443","id":"uuid-2","aid":"0",` +
		`"scy":"auto","net":"ws","type":"none","host":"de.example.com","path":"/vm","tls":"tls","sni":"","fp":"chrome"}`
	link, err := Parse("vmess://" + base64.StdEncoding.EncodeToString([]byte(body)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if link.Name != "Germany" || link.Port != 443 {
		t.Fatalf("unexpected link header: %+v", link)
	}
	want := map[string]any{
		"type":            "vmess",
		"server":          "de.example.com",
		"server_port":     443,
		"uuid":            "uuid-2",
		"security":        "auto",
		"alter_id":        0,
		"packet_encoding": "xudp",
		"tls": map[string]any{
			"enabled":     true,
			"server_name": "de.example.com",
			"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
		},
		"transport": map[string]any{
			"type":    "ws",
			"path":    "/vm",
			"headers": map[string]any{"Host": "de.example.com"},
		},
	}
	assertOutbound(t, link.Outbound, want)
}

func TestParseVMessNumericPortURLSafe(t *testing.T) {
	body := `{"add":"1.1.1.1","port":8080,"id":"u","aid":0,"net":"tcp","tls":""}`
	link, err := Parse("vmess://" + base64.RawURLEncoding.EncodeToString([]byte(body)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if link.Port != 8080 {
		t.Fatalf("port = %d, want 8080", link.Port)
	}
	if _, ok := link.Outbound["transport"]; ok {
		t.Fatalf("tcp vmess must not have a transport: %v", link.Outbound)
	}
}

func TestParseTrojanDefaultsToTLS(t *testing.T) {
	link, err := Parse("trojan://p%40ss@tr.example.com:443?sni=front.example.com#tr")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string]any{
		"type":        "trojan",
		"server":      "tr.example.com",
		"server_port": 443,
		"password":    "p@ss",
		"tls":         map[string]any{"enabled": true, "server_name": "front.example.com"},
	}
	assertOutbound(t, link.Outbound, want)
}

func TestParseShadowsocksFormats(t *testing.T) {
	userInfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret"))
	legacy := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@9.9.9.9:8388"))
	tests := []struct {
		name, raw, method, password, server string
		port                                int
	}{
		{"sip002 base64", "ss://" + userInfo + "@ss.example.com:8388#ss", "aes-256-gcm", "secret", "ss.example.com", 8388},
		{"sip002 plain 2022", "ss://2022-blake3-aes-128-gcm:a2V5%3D@[2001:db8::1]:443", "2022-blake3-aes-128-gcm", "a2V5=", "2001:db8::1", 443},
		{"legacy", "ss://" + legacy + "#old", "chacha20-ietf-poly1305", "pw", "9.9.9.9", 8388},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link, err := Parse(tt.raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			want := map[string]any{
				"type":        "shadowsocks",
				"server":      tt.server,
				"server_port": tt.port,
				"method":      tt.method,
				"password":    tt.password,
			}
			assertOutbound(t, link.Outbound, want)
		})
	}
}

func TestParseShadowsocksPlugin(t *testing.T) {
	userInfo := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw"))
	link, err := Parse("ss://" + userInfo + "@h.example:443/?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if link.Outbound["plugin"] != "obfs-local" || link.Outbound["plugin_opts"] != "obfs=http;obfs-host=example.com" {
		t.Fatalf("unexpected plugin fields: %v", link.Outbound)
	}
}

func TestParseHysteria2(t *testing.T) {
	link, err := Parse("hy2://auth:part@hy.example.com:443?obfs=salamander&obfs-password=x&sni=real.example.com&insecure=1#hy")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string]any{
		"type":        "hysteria2",
		"server":      "hy.example.com",
		"server_port": 443,
		"password":    "auth:part",
		"obfs":        map[string]any{"type": "salamander", "password": "x"},
		"tls": map[string]any{
			"enabled":     true,
			"server_name": "real.example.com",
			"insecure":    true,
			"alpn":        []string{"h3"},
		},
	}
	assertOutbound(t, link.Outbound, want)
}

func TestParseHysteria2PortHopping(t *testing.T) {
	link, err := Parse("hysteria2://pw@hy.example.com:443,20000-30000/?sni=hy.example.com#hop")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if link.Port != 443 || link.Name != "hop" {
		t.Fatalf("unexpected link header: %+v", link)
	}
	if got := link.Outbound["server_ports"]; !reflect.DeepEqual(got, []string{"443:443", "20000:30000"}) {
		t.Fatalf("server_ports = %v", got)
	}
}

func TestParseTUIC(t *testing.T) {
	link, err := Parse("tuic://uuid-3:pw@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=quic&alpn=h3#t")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string]any{
		"type":               "tuic",
		"server":             "tuic.example.com",
		"server_port":        443,
		"uuid":               "uuid-3",
		"password":           "pw",
		"congestion_control": "bbr",
		"udp_relay_mode":     "quic",
		"tls": map[string]any{
			"enabled":     true,
			"server_name": "tuic.example.com",
			"alpn":        []string{"h3"},
		},
	}
	assertOutbound(t, link.Outbound, want)
}

func TestParseErrors(t *testing.T) {
	tests := []string{
		"",
		"not a link",
		"socks5://user@host:1080",
		"vless://@host:443",
		"vless://id@host:99999",
		"vless://id@host:443?security=reality",
		"vless://id@host:443?type=kcp",
		"vmess://!!!",
		"ss://bm90LWEtdmFsaWQ@host:1",
		"tuic://onlyuuid@host:443",
	}
	for _, raw := range tests {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", raw)
		}
	}
	if _, err := Parse("socks5://u@h:1"); !errors.Is(err, ErrUnsupportedScheme) {
		t.Errorf("unsupported scheme error = %v, want ErrUnsupportedScheme", err)
	}
}

func TestGatewayConfig(t *testing.T) {
	link, err := Parse("trojan://pw@tr.example.com:443")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	raw, err := GatewayConfig(link)
	if err != nil {
		t.Fatalf("GatewayConfig: %v", err)
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
		Inbounds  []map[string]any `json:"inbounds"`
		Route     map[string]any   `json:"route"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	if len(cfg.Outbounds) != 2 || cfg.Outbounds[0]["tag"] != "proxy" || cfg.Outbounds[0]["type"] != "trojan" {
		t.Fatalf("unexpected outbounds: %v", cfg.Outbounds)
	}
	if cfg.Inbounds[0]["type"] != "tun" || cfg.Inbounds[0]["auto_route"] != true {
		t.Fatalf("unexpected inbound: %v", cfg.Inbounds[0])
	}
	if cfg.Route["final"] != "proxy" {
		t.Fatalf("route.final = %v, want proxy", cfg.Route["final"])
	}
	if _, ok := link.Outbound["tag"]; ok {
		t.Fatal("GatewayConfig must not mutate the link's outbound")
	}
}

// assertOutbound compares through a JSON round trip so that []string vs
// []any and int vs float64 differences don't matter.
func assertOutbound(t *testing.T, got, want map[string]any) {
	t.Helper()
	if !reflect.DeepEqual(normalize(t, got), normalize(t, want)) {
		g, _ := json.MarshalIndent(got, "", "  ")
		w, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("outbound mismatch\n got: %s\nwant: %s", g, w)
	}
}

func normalize(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}
