package proxylink

import (
	"encoding/json"
	"maps"
)

// proxyTag is the tag of the outbound built from the share link.
const proxyTag = "proxy"

// GatewayConfig returns a sing-box configuration that turns the container it
// runs in into a layer-3 gateway: traffic the router forwards to the
// container's veth address enters a TUN device (auto_route) and leaves through
// the proxy described by link.
//
// Private ranges are kept off the TUN so that replies to LAN clients go back
// out through the veth instead of looping into the proxy, and DNS sent through
// the gateway is answered over DNS-over-TLS tunnelled through the proxy.
func GatewayConfig(link *Link) ([]byte, error) {
	outbound := maps.Clone(link.Outbound)
	outbound["tag"] = proxyTag

	config := map[string]any{
		"log": map[string]any{
			"level":     "warn",
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "tls", "tag": "dns-remote", "server": "1.1.1.1", "detour": proxyTag},
				// Resolves the proxy server's own hostname, outside the tunnel.
				map[string]any{"type": "tls", "tag": "dns-bootstrap", "server": "1.1.1.1"},
			},
			"final":    "dns-remote",
			"strategy": "ipv4_only",
		},
		"inbounds": []any{
			map[string]any{
				"type":           "tun",
				"tag":            "tun-in",
				"interface_name": "tun0",
				"address":        []string{"172.19.0.1/30"},
				"auto_route":     true,
				// Without strict_route (or auto_redirect) sing-box keeps all
				// ICMP off the TUN, so the router's netwatch pings would bypass
				// the tunnel entirely.
				"strict_route": true,
				"dns_mode":     "disabled",
				"route_exclude_address": []string{
					"10.0.0.0/8",
					"100.64.0.0/10",
					"169.254.0.0/16",
					"172.16.0.0/12",
					"192.168.0.0/16",
					"224.0.0.0/4",
				},
				"stack": "gvisor",
			},
		},
		"outbounds": []any{
			outbound,
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{"ip_is_private": true, "outbound": "direct"},
			},
			"final":                   proxyTag,
			"auto_detect_interface":   true,
			"default_domain_resolver": "dns-bootstrap",
		},
	}

	return json.MarshalIndent(config, "", "  ")
}

// GatewayEntrypoint is the shell script the gateway container runs. It makes
// the container forward packets between its veth and the TUN, creates the TUN
// device node when the runtime does not provide one (RouterOS containers
// don't), then hands over to sing-box.
const GatewayEntrypoint = `#!/bin/sh
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
if [ ! -c /dev/net/tun ]; then
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200
fi
exec sing-box run -c /etc/sing-box/config.json
`
