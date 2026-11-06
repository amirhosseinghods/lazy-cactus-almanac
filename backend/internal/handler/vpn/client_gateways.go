package vpn

import (
	"strings"

	"nasnet-panel/pkg/routeros"
)

// ClientGateway is a VPN client and the route gateway that sends traffic into it.
type ClientGateway struct {
	Name    string
	Label   string
	Type    string
	Running bool
	// Gateway is empty for a V2Ray client that is not running yet.
	Gateway string
}

// ListClientGateways lists the router's VPN clients (WireGuard, L2TP and the
// other PPP types, V2Ray) with the gateway a route needs to use each one.
func ListClientGateways(client *routeros.Client) ([]ClientGateway, error) {
	ifaces, err := client.ListVPNClients()
	if err != nil {
		return nil, err
	}
	out := []ClientGateway{}
	for _, v := range ifaces {
		if v.Type == "wg" && !isWireGuardClient(client, v.Name) {
			continue
		}
		out = append(out, ClientGateway{Name: v.Name, Label: labelOr(v.Comment, v.Name), Type: v.Type, Running: !v.Disabled && v.Running, Gateway: v.Name})
	}
	// The container package may be missing; the other clients still count.
	v2ray, _ := listV2RayClients(client)
	for _, v := range v2ray {
		gw, err := ResolveV2RayGateway(client, v.Name)
		if err != nil {
			gw = ""
		}
		out = append(out, ClientGateway{Name: v.Name, Label: labelOr(v.Comment, v.Name), Type: "v2ray", Running: v.Running && gw != "", Gateway: gw})
	}
	return out, nil
}

// isWireGuardClient tells a WireGuard client from a server sharing the
// interface type: the panel names its clients *-client, and a client made
// elsewhere still has a peer with an endpoint to dial, which a server's
// peers (the people dialling in) do not.
func isWireGuardClient(client *routeros.Client, name string) bool {
	if strings.HasSuffix(name, "-client") {
		return true
	}
	peers, err := client.GetWireGuardPeers(name)
	if err != nil {
		return false
	}
	for _, p := range peers {
		if p.EndpointAddress != "" {
			return true
		}
	}
	return false
}

func labelOr(label, name string) string {
	if label != "" {
		return label
	}
	return name
}
