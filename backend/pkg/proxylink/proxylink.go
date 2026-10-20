// Package proxylink parses V2Ray-style proxy share links (vless://, vmess://,
// trojan://, ss://, hysteria2://, hy2:// and tuic://) into sing-box outbound
// definitions.
package proxylink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Protocol names, as reported in Link.Protocol.
const (
	ProtocolVLESS       = "vless"
	ProtocolVMess       = "vmess"
	ProtocolTrojan      = "trojan"
	ProtocolShadowsocks = "shadowsocks"
	ProtocolHysteria2   = "hysteria2"
	ProtocolTUIC        = "tuic"
)

// ErrUnsupportedScheme is returned for links whose scheme is not one of the
// supported proxy protocols.
var ErrUnsupportedScheme = errors.New("unsupported link scheme")

// Link is a parsed proxy share link.
type Link struct {
	// Protocol is one of the Protocol* constants.
	Protocol string
	// Name is the human-readable label carried in the link (the URL fragment,
	// or "ps" for vmess), possibly empty.
	Name string
	// Server and Port are the proxy server's address.
	Server string
	Port   int
	// Outbound is the sing-box outbound object for this link, without a tag.
	Outbound map[string]any
}

// Parse parses a single proxy share link.
func Parse(raw string) (*Link, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("link is empty")
	}
	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, errors.New("link has no scheme")
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return parseVLESS(raw)
	case "vmess":
		return parseVMess(raw)
	case "trojan":
		return parseTrojan(raw)
	case "ss":
		return parseShadowsocks(raw)
	case "hysteria2", "hy2":
		return parseHysteria2(raw)
	case "tuic":
		return parseTUIC(raw)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedScheme, scheme)
	}
}

func parseVLESS(raw string) (*Link, error) {
	u, err := parseURL(raw)
	if err != nil {
		return nil, err
	}
	link, err := newLink(ProtocolVLESS, u)
	if err != nil {
		return nil, err
	}
	uuid := u.User.Username()
	if uuid == "" {
		return nil, errors.New("vless link is missing the user id")
	}
	q := u.Query()
	out := link.Outbound
	out["uuid"] = uuid
	out["packet_encoding"] = "xudp"
	if flow := q.Get("flow"); flow != "" {
		out["flow"] = flow
	}
	if err := applyStreamSettings(out, q, link.Server, q.Get("security")); err != nil {
		return nil, err
	}
	return link, nil
}

func parseTrojan(raw string) (*Link, error) {
	u, err := parseURL(raw)
	if err != nil {
		return nil, err
	}
	link, err := newLink(ProtocolTrojan, u)
	if err != nil {
		return nil, err
	}
	password := u.User.Username()
	if password == "" {
		return nil, errors.New("trojan link is missing the password")
	}
	q := u.Query()
	link.Outbound["password"] = password
	// Trojan always runs over TLS unless the link explicitly opts out.
	security := q.Get("security")
	if security == "" {
		security = "tls"
	}
	if err := applyStreamSettings(link.Outbound, q, link.Server, security); err != nil {
		return nil, err
	}
	return link, nil
}

// vmessJSON is the base64-encoded JSON body of a vmess:// link (the
// "v2rayN" format). Port and aid are sometimes numbers, sometimes strings.
type vmessJSON struct {
	PS       string          `json:"ps"`
	Add      string          `json:"add"`
	Port     json.RawMessage `json:"port"`
	ID       string          `json:"id"`
	Aid      json.RawMessage `json:"aid"`
	Scy      string          `json:"scy"`
	Net      string          `json:"net"`
	Type     string          `json:"type"`
	Host     string          `json:"host"`
	Path     string          `json:"path"`
	TLS      string          `json:"tls"`
	SNI      string          `json:"sni"`
	ALPN     string          `json:"alpn"`
	FP       string          `json:"fp"`
	Insecure json.RawMessage `json:"allowInsecure"`
}

func parseVMess(raw string) (*Link, error) {
	body := raw[len("vmess://"):]
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	decoded, err := decodeBase64(body)
	if err != nil {
		return nil, fmt.Errorf("vmess link body is not valid base64: %w", err)
	}
	var v vmessJSON
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, fmt.Errorf("vmess link body is not valid JSON: %w", err)
	}
	if v.Add == "" || v.ID == "" {
		return nil, errors.New("vmess link is missing the server address or user id")
	}
	port, err := flexibleInt(v.Port)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("vmess link has an invalid port")
	}
	alterID, _ := flexibleInt(v.Aid)
	security := v.Scy
	if security == "" {
		security = "auto"
	}

	out := map[string]any{
		"type":            ProtocolVMess,
		"server":          v.Add,
		"server_port":     port,
		"uuid":            v.ID,
		"security":        security,
		"alter_id":        alterID,
		"packet_encoding": "xudp",
	}

	// Translate the v2rayN fields into the query-string vocabulary used by the
	// other link formats so the stream settings are handled in one place.
	q := url.Values{}
	q.Set("type", v.Net)
	q.Set("headerType", v.Type)
	q.Set("host", v.Host)
	q.Set("path", v.Path)
	q.Set("sni", v.SNI)
	q.Set("alpn", v.ALPN)
	q.Set("fp", v.FP)
	if insecure, _ := flexibleInt(v.Insecure); insecure == 1 || strings.EqualFold(strings.Trim(string(v.Insecure), `"`), "true") {
		q.Set("allowInsecure", "1")
	}
	if v.Net == "grpc" {
		q.Set("serviceName", v.Path)
	}
	if err := applyStreamSettings(out, q, v.Add, v.TLS); err != nil {
		return nil, err
	}

	return &Link{Protocol: ProtocolVMess, Name: v.PS, Server: v.Add, Port: port, Outbound: out}, nil
}

func parseShadowsocks(raw string) (*Link, error) {
	body := raw[len("ss://"):]
	name := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		name, _ = url.PathUnescape(body[i+1:])
		body = body[:i]
	}
	query := ""
	if i := strings.IndexByte(body, '?'); i >= 0 {
		query = body[i+1:]
		body = body[:i]
	}
	body = strings.TrimSuffix(body, "/")

	var userInfo, hostPort string
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		// SIP002: ss://base64(method:password)@host:port, where the user info
		// may instead be percent-encoded plain text (common for 2022 ciphers).
		userInfo, hostPort = body[:at], body[at+1:]
		if decoded, err := decodeBase64(userInfo); err == nil && strings.Contains(string(decoded), ":") {
			userInfo = string(decoded)
		} else if unescaped, err := url.PathUnescape(userInfo); err == nil {
			userInfo = unescaped
		}
	} else {
		// Legacy: ss://base64(method:password@host:port).
		decoded, err := decodeBase64(body)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks link body is not valid base64: %w", err)
		}
		at := strings.LastIndexByte(string(decoded), '@')
		if at < 0 {
			return nil, errors.New("shadowsocks link is missing the server address")
		}
		userInfo, hostPort = string(decoded[:at]), string(decoded[at+1:])
	}

	method, password, ok := strings.Cut(userInfo, ":")
	if !ok || method == "" || password == "" {
		return nil, errors.New("shadowsocks link is missing the method or password")
	}
	server, port, err := splitHostPort(hostPort)
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"type":        ProtocolShadowsocks,
		"server":      server,
		"server_port": port,
		"method":      method,
		"password":    password,
	}
	if query != "" {
		q, err := url.ParseQuery(query)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks link has an invalid query: %w", err)
		}
		if plugin := q.Get("plugin"); plugin != "" {
			pluginName, opts, _ := strings.Cut(plugin, ";")
			if pluginName == "simple-obfs" {
				pluginName = "obfs-local"
			}
			out["plugin"] = pluginName
			if opts != "" {
				out["plugin_opts"] = opts
			}
		}
	}

	return &Link{Protocol: ProtocolShadowsocks, Name: name, Server: server, Port: port, Outbound: out}, nil
}

func parseHysteria2(raw string) (*Link, error) {
	u, err := parseURL(raw)
	if err != nil {
		return nil, err
	}
	link, err := newLink(ProtocolHysteria2, u)
	if err != nil {
		return nil, err
	}
	// The whole user-info is the auth string; one containing ":" is split by
	// net/url into username and password, so glue it back together.
	var password string
	if pw, ok := u.User.Password(); ok {
		password = u.User.Username() + ":" + pw
	} else {
		password = u.User.Username()
	}
	if password == "" {
		return nil, errors.New("hysteria2 link is missing the password")
	}
	q := u.Query()
	out := link.Outbound
	out["password"] = password
	if obfs := q.Get("obfs"); obfs != "" && obfs != "none" {
		out["obfs"] = map[string]any{"type": obfs, "password": q.Get("obfs-password")}
	}
	if ports := q.Get("mport"); ports != "" {
		out["server_ports"] = hopPorts(ports)
	}
	out["tls"] = tlsOptions(q, link.Server, "h3")
	return link, nil
}

func parseTUIC(raw string) (*Link, error) {
	u, err := parseURL(raw)
	if err != nil {
		return nil, err
	}
	link, err := newLink(ProtocolTUIC, u)
	if err != nil {
		return nil, err
	}
	uuid := u.User.Username()
	password, _ := u.User.Password()
	if uuid == "" || password == "" {
		return nil, errors.New("tuic link is missing the uuid or password")
	}
	q := u.Query()
	out := link.Outbound
	out["uuid"] = uuid
	out["password"] = password
	if cc := firstNonEmpty(q.Get("congestion_control"), q.Get("congestion-control")); cc != "" {
		out["congestion_control"] = cc
	}
	if mode := firstNonEmpty(q.Get("udp_relay_mode"), q.Get("udp-relay-mode")); mode != "" {
		out["udp_relay_mode"] = mode
	}
	out["tls"] = tlsOptions(q, link.Server, "h3")
	return link, nil
}

// applyStreamSettings sets the "tls" and "transport" fields of an outbound
// from the Xray-style query parameters shared by vless, vmess and trojan
// links.
func applyStreamSettings(out map[string]any, q url.Values, server, security string) error {
	switch strings.ToLower(security) {
	case "", "none":
	case "tls", "xtls":
		out["tls"] = tlsOptions(q, server, "")
	case "reality":
		publicKey := q.Get("pbk")
		if publicKey == "" {
			return errors.New("reality link is missing the public key (pbk)")
		}
		tls := tlsOptions(q, server, "")
		tls["reality"] = map[string]any{
			"enabled":    true,
			"public_key": publicKey,
			"short_id":   q.Get("sid"),
		}
		// REALITY requires a uTLS fingerprint; chrome is what Xray clients
		// default to when the link omits one.
		if _, ok := tls["utls"]; !ok {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		}
		out["tls"] = tls
	default:
		return fmt.Errorf("unsupported security %q", security)
	}

	transport, err := transportOptions(q)
	if err != nil {
		return err
	}
	if transport != nil {
		out["transport"] = transport
	}
	return nil
}

func transportOptions(q url.Values) (map[string]any, error) {
	network := strings.ToLower(q.Get("type"))
	host := q.Get("host")
	path := q.Get("path")
	switch network {
	case "", "tcp", "raw":
		if strings.EqualFold(q.Get("headerType"), "http") {
			t := map[string]any{"type": "http", "method": "GET"}
			if host != "" {
				t["host"] = splitList(host)
			}
			if path != "" {
				t["path"] = path
			}
			return t, nil
		}
		return nil, nil
	case "ws", "websocket":
		t := map[string]any{"type": "ws"}
		// Xray encodes early data as "/path?ed=2048"; sing-box wants it split
		// out and sent in Sec-WebSocket-Protocol to stay compatible.
		if p, ed, ok := strings.Cut(path, "?ed="); ok {
			path = p
			if n, err := strconv.Atoi(ed); err == nil && n > 0 {
				t["max_early_data"] = n
				t["early_data_header_name"] = "Sec-WebSocket-Protocol"
			}
		}
		if path != "" {
			t["path"] = path
		}
		if host != "" {
			t["headers"] = map[string]any{"Host": host}
		}
		return t, nil
	case "grpc":
		t := map[string]any{"type": "grpc"}
		if name := q.Get("serviceName"); name != "" {
			t["service_name"] = name
		}
		return t, nil
	case "http", "h2":
		t := map[string]any{"type": "http"}
		if host != "" {
			t["host"] = splitList(host)
		}
		if path != "" {
			t["path"] = path
		}
		return t, nil
	case "httpupgrade":
		t := map[string]any{"type": "httpupgrade"}
		if host != "" {
			t["host"] = host
		}
		if path != "" {
			t["path"] = path
		}
		return t, nil
	default:
		return nil, fmt.Errorf("unsupported transport %q", network)
	}
}

func tlsOptions(q url.Values, server, defaultALPN string) map[string]any {
	tls := map[string]any{"enabled": true}
	sni := firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("host"))
	if sni == "" && net.ParseIP(server) == nil {
		sni = server
	}
	if sni != "" {
		tls["server_name"] = sni
	}
	if isTruthy(q.Get("allowInsecure")) || isTruthy(q.Get("insecure")) || isTruthy(q.Get("allow_insecure")) {
		tls["insecure"] = true
	}
	alpn := q.Get("alpn")
	if alpn == "" {
		alpn = defaultALPN
	}
	if alpn != "" {
		tls["alpn"] = splitList(alpn)
	}
	if fp := q.Get("fp"); fp != "" && fp != "none" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	return tls
}

func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// Port-hopping hysteria2 links ("host:443,8000-9000") fail url.Parse;
		// retry with the port range moved into the mport parameter.
		fixed, ok := moveHopPorts(raw)
		if !ok {
			return nil, fmt.Errorf("invalid link: %w", err)
		}
		if u, err = url.Parse(fixed); err != nil {
			return nil, fmt.Errorf("invalid link: %w", err)
		}
	}
	if u.User == nil {
		return nil, errors.New("link is missing the user credentials")
	}
	return u, nil
}

// moveHopPorts rewrites "scheme://auth@host:443,8000-9000/?q" into
// "scheme://auth@host:443/?q&mport=443,8000-9000".
func moveHopPorts(raw string) (string, bool) {
	at := strings.LastIndexByte(raw, '@')
	if at < 0 {
		return "", false
	}
	rest := raw[at+1:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	hostPort := rest[:end]
	colon := strings.LastIndexByte(hostPort, ':')
	if colon < 0 || !strings.ContainsAny(hostPort[colon+1:], ",-") {
		return "", false
	}
	ports := hostPort[colon+1:]
	first := strings.FieldsFunc(ports, func(r rune) bool { return r == ',' || r == '-' })
	if len(first) == 0 {
		return "", false
	}
	tail := rest[end:]
	frag := ""
	if i := strings.IndexByte(tail, '#'); i >= 0 {
		frag, tail = tail[i:], tail[:i]
	}
	sep := "?"
	if strings.Contains(tail, "?") {
		sep = "&"
	}
	return raw[:at+1] + hostPort[:colon+1] + first[0] + tail + sep + "mport=" + url.QueryEscape(ports) + frag, true
}

// hopPorts converts "443,8000-9000" into sing-box's ["443:443", "8000:9000"].
func hopPorts(spec string) []string {
	var out []string
	for _, part := range splitList(spec) {
		lo, hi, ok := strings.Cut(part, "-")
		if !ok {
			hi = lo
		}
		out = append(out, strings.TrimSpace(lo)+":"+strings.TrimSpace(hi))
	}
	return out
}

func newLink(protocol string, u *url.URL) (*Link, error) {
	server := u.Hostname()
	if server == "" {
		return nil, fmt.Errorf("%s link is missing the server address", protocol)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%s link has an invalid port", protocol)
	}
	return &Link{
		Protocol: protocol,
		Name:     u.Fragment,
		Server:   server,
		Port:     port,
		Outbound: map[string]any{
			"type":        protocol,
			"server":      server,
			"server_port": port,
		},
	}, nil
}

func splitHostPort(hostPort string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", 0, fmt.Errorf("invalid server address %q: %w", hostPort, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || host == "" {
		return "", 0, fmt.Errorf("invalid server address %q", hostPort)
	}
	return host, port, nil
}

// decodeBase64 accepts standard and URL-safe alphabets, with or without padding.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func flexibleInt(raw json.RawMessage) (int, error) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" {
		return 0, nil
	}
	return strconv.Atoi(s)
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func isTruthy(s string) bool {
	return s == "1" || strings.EqualFold(s, "true")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
