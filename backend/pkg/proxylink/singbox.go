package proxylink

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
)

// ProxyTag is the tag traffic is routed to: the single server's outbound, or
// the urltest group picking among several servers.
const ProxyTag = "proxy"

// ClashAPIPort is where the gateway exposes sing-box's Clash API (when
// GatewayOptions.ClashAPISecret is set), used to read which server urltest
// selected.
const ClashAPIPort = 9090

// URLTestURL is probed through every server to pick the fastest one.
const URLTestURL = "https://www.gstatic.com/generate_204"

// GatewayOptions tunes GatewayConfig.
type GatewayOptions struct {
	// ClashAPISecret enables the Clash API on ClashAPIPort, protected by this
	// secret. Empty leaves the API off.
	ClashAPISecret string
}

// ServerTag is the outbound tag of the i-th (0-based) server when a gateway
// has several servers.
func ServerTag(i int) string {
	return fmt.Sprintf("server-%d", i+1)
}

// GatewayConfig returns a sing-box configuration that turns the container it
// runs in into a layer-3 gateway: traffic the router forwards to the
// container's veth address enters a TUN device (auto_route) and leaves through
// the proxy. With several links, a urltest group keeps traffic on whichever
// server currently answers fastest.
//
// Nothing a LAN client sends can leave the container directly: the only
// direct route is for private ranges, DNS is hijacked and answered over
// DNS-over-TLS through the proxy, and IPv6 is rejected rather than risk it
// bypassing the IPv4-only tunnel. Private ranges are kept off the TUN so that
// replies to LAN clients go back out through the veth instead of looping.
func GatewayConfig(links []*Link, opts GatewayOptions) ([]byte, error) {
	if len(links) == 0 {
		return nil, errors.New("at least one link is required")
	}

	var outbounds []any
	if len(links) == 1 {
		out := maps.Clone(links[0].Outbound)
		out["tag"] = ProxyTag
		outbounds = append(outbounds, out)
	} else {
		tags := make([]string, len(links))
		for i := range links {
			tags[i] = ServerTag(i)
		}
		outbounds = append(outbounds, map[string]any{
			"type":      "urltest",
			"tag":       ProxyTag,
			"outbounds": tags,
			"url":       URLTestURL,
			// Probing every server costs router CPU and data; a slow cadence
			// and a wide tolerance keep switches to real latency changes.
			"interval":  "5m",
			"tolerance": 100,
		})
		for i, link := range links {
			out := maps.Clone(link.Outbound)
			out["tag"] = tags[i]
			outbounds = append(outbounds, out)
		}
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	config := map[string]any{
		"log": map[string]any{
			"level":     "warn",
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "tls", "tag": "dns-remote", "server": "1.1.1.1", "detour": ProxyTag},
				// Resolves the proxy servers' own hostnames, outside the tunnel.
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
				// The kernel stack avoids running a userspace TCP/IP stack
				// on the router's CPU.
				"stack": "system",
			},
		},
		"outbounds": outbounds,
		"route": map[string]any{
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{"ip_version": 6, "action": "reject"},
				map[string]any{"ip_is_private": true, "outbound": "direct"},
			},
			"final":                   ProxyTag,
			"auto_detect_interface":   true,
			"default_domain_resolver": "dns-bootstrap",
		},
	}
	if opts.ClashAPISecret != "" {
		config["experimental"] = map[string]any{
			"clash_api": map[string]any{
				"external_controller": fmt.Sprintf("0.0.0.0:%d", ClashAPIPort),
				"secret":              opts.ClashAPISecret,
			},
		}
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
