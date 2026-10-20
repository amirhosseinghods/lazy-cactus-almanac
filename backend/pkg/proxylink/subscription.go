package proxylink

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaxSubscriptionLinks caps how many servers one subscription contributes,
// keeping the generated config within what RouterOS can write to a file and
// what urltest can probe without loading the router's CPU.
const MaxSubscriptionLinks = 20

// SubscriptionResult is the outcome of parsing a subscription body.
type SubscriptionResult struct {
	Links []*Link
	// Skipped counts entries that were recognised as servers but could not
	// be used (unsupported scheme, malformed link, unsupported outbound type).
	Skipped int
	// Truncated counts usable servers dropped beyond MaxSubscriptionLinks.
	Truncated int
}

// ParseSubscription parses a subscription body: a plain or base64-encoded
// list of share links (one per line), or a sing-box JSON config whose proxy
// outbounds are reused as-is.
func ParseSubscription(body []byte) (*SubscriptionResult, error) {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return nil, fmt.Errorf("subscription is empty")
	}

	var res *SubscriptionResult
	if strings.HasPrefix(text, "{") {
		var err error
		if res, err = parseSingBoxSubscription([]byte(text)); err != nil {
			return nil, err
		}
	} else {
		if !strings.Contains(text, "://") {
			decoded, err := decodeBase64(strings.Join(strings.Fields(text), ""))
			if err != nil {
				return nil, fmt.Errorf("subscription is neither a link list nor base64: %w", err)
			}
			text = string(decoded)
		}
		res = parseLinkList(text)
	}

	if len(res.Links) > MaxSubscriptionLinks {
		res.Truncated = len(res.Links) - MaxSubscriptionLinks
		res.Links = res.Links[:MaxSubscriptionLinks]
	}
	if len(res.Links) == 0 {
		return nil, fmt.Errorf("subscription contains no supported servers (%d skipped)", res.Skipped)
	}
	return res, nil
}

func parseLinkList(text string) *SubscriptionResult {
	res := &SubscriptionResult{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		link, err := Parse(line)
		if err != nil {
			res.Skipped++
			continue
		}
		res.Links = append(res.Links, link)
	}
	return res
}

// singBoxOutboundTypes are the outbound types reused from a sing-box JSON
// subscription. Everything else (direct, block, selector, urltest, dns and
// so on) is routing plumbing rather than a server.
var singBoxOutboundTypes = map[string]bool{
	ProtocolVLESS:       true,
	ProtocolVMess:       true,
	ProtocolTrojan:      true,
	ProtocolShadowsocks: true,
	ProtocolHysteria2:   true,
	ProtocolTUIC:        true,
}

func parseSingBoxSubscription(body []byte) (*SubscriptionResult, error) {
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("subscription is not valid sing-box JSON: %w", err)
	}

	res := &SubscriptionResult{}
	for _, out := range cfg.Outbounds {
		typ := stringField(out, "type")
		switch {
		case singBoxOutboundTypes[typ]:
		case typ == "direct" || typ == "block" || typ == "dns" || typ == "selector" || typ == "urltest":
			continue
		default:
			res.Skipped++
			continue
		}
		server := stringField(out, "server")
		port, ok := out["server_port"].(float64)
		if !ok {
			port = 0
		}
		if server == "" || port < 1 || port > 65535 {
			res.Skipped++
			continue
		}
		name := stringField(out, "tag")
		outbound := make(map[string]any, len(out))
		for k, v := range out {
			// Tags are reassigned, and dial fields such as detour or
			// bind_interface would reference this subscription's own config.
			if k == "tag" || k == "detour" || k == "bind_interface" {
				continue
			}
			outbound[k] = v
		}
		res.Links = append(res.Links, &Link{
			Protocol: typ,
			Name:     name,
			Server:   server,
			Port:     int(port),
			Outbound: outbound,
		})
	}
	return res, nil
}

func stringField(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}
