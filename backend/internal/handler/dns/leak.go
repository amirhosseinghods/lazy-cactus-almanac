package dns

import (
	"errors"
	"nasnet-panel/internal/handler/common"
	"nasnet-panel/internal/handler/plugin"
	"nasnet-panel/internal/handler/vpn"
	"net/http"
	"slices"
	"strings"

	"nasnet-panel/pkg/routeros"

	"github.com/labstack/echo/v4"
)

// The router resolves names through 1.0.0.1 and 1.1.1.1, reached over the
// VPN or the foreign link by host routes that check their gateway. When such
// a route goes down, the query falls through to the next default route,
// which may be the domestic link, whose ISP intercepts port 53 and answers
// itself, revealing what is being looked up. The setup wizard also lists the
// domestic ISP's resolver among the router's DNS servers as a fallback, and
// RouterOS spreads queries across all of them, so part of every lookup went
// to the domestic resolver directly.
//
// DNS leak protection keeps only the resolvers routed through the VPN (when
// there are any), so lookups leave from the VPN's location rather than
// revealing the domestic ISP or the Starlink point of presence. .ir names
// keep their own forward rule to the domestic resolver. It also adds a
// last-resort blackhole for the resolvers, so a failed tunnel makes DNS fail
// instead of leak.
const (
	dnsLeakGuardComment = "nasnet-dns-leak-guard"
	// Remembers the domestic servers taken out of the list, so turning the
	// protection off puts them back.
	dnsLeakGuardRemovedFile = "dns-leak-guard-removed.txt"
)

// dnsLeakGuardResolvers are the resolvers the NasNet layout routes over the
// tunnel or foreign link.
var dnsLeakGuardResolvers = []string{"1.0.0.1/32", "1.1.1.1/32"}

func dnsLeakGuardRoutes(client *routeros.Client) ([]routeros.IPRouteInfo, error) {
	return client.ListIPRoutesWithFilters(routeros.IPRouteFilter{Comment: dnsLeakGuardComment})
}

func dnsLeakGuardRemovedPath(client *routeros.Client) string {
	return plugin.StoragePrefix(client) + routeros.NasnetPanelDir + "/" + dnsLeakGuardRemovedFile
}

// leakyDNSServers returns the DNS servers that do not go through the VPN:
// those the NasNet layout routes over the domestic link, and, when at least
// one server is routed through the VPN, every server that isn't. Host routes
// are recognised by their comments (Route-to-VPN-Client, Route-to-Domestic...).
func leakyDNSServers(client *routeros.Client, servers []string) (map[string]bool, error) {
	routes, err := client.ListIPRoutesWithFilters(routeros.IPRouteFilter{RoutingTable: "main"})
	if err != nil {
		return nil, err
	}
	routeComment := func(server string) string {
		for _, r := range routes {
			if r.DstAddress == server+"/32" {
				return r.Comment
			}
		}
		return ""
	}
	anyVPN := false
	for _, server := range servers {
		if strings.HasPrefix(routeComment(server), vpn.VPNRoutesComment) {
			anyVPN = true
		}
	}
	leaky := map[string]bool{}
	for _, server := range servers {
		comment := routeComment(server)
		if strings.HasPrefix(comment, "Route-to-Domestic") || (anyVPN && !strings.HasPrefix(comment, vpn.VPNRoutesComment)) {
			leaky[server] = true
		}
	}
	return leaky, nil
}

func dnsLeakGuardEnabled(client *routeros.Client) (bool, error) {
	routes, err := dnsLeakGuardRoutes(client)
	if err != nil || len(routes) < len(dnsLeakGuardResolvers) {
		return false, err
	}
	info, err := client.GetDNSInfo()
	if err != nil {
		return false, err
	}
	domestic, err := leakyDNSServers(client, info.Servers)
	if err != nil {
		return false, err
	}
	return len(domestic) == 0, nil
}

// setDomesticDNSServers takes the resolvers outside the VPN out of the
// router's DNS servers (remembering them) or puts them back.
func setDomesticDNSServers(client *routeros.Client, remove bool) error {
	info, err := client.GetDNSInfo()
	if err != nil {
		return err
	}
	path := dnsLeakGuardRemovedPath(client)
	if remove {
		domestic, err := leakyDNSServers(client, info.Servers)
		if err != nil || len(domestic) == 0 {
			return err
		}
		var keep, removed []string
		for _, s := range info.Servers {
			if domestic[s] {
				removed = append(removed, s)
			} else {
				keep = append(keep, s)
			}
		}
		if len(keep) == 0 {
			return errors.New("the router has no DNS server that avoids the domestic link; add a foreign DNS server first")
		}
		if err := client.AddFile(path, strings.Join(removed, ",")); err != nil {
			return err
		}
		servers := strings.Join(keep, ",")
		return client.UpdateDNSConfig(routeros.DNSUpdateConfig{Servers: &servers})
	}

	raw, err := client.GetFileContents(path, 0)
	if err != nil || strings.TrimSpace(raw) == "" {
		// Nothing was taken out by the panel.
		return nil //nolint:nilerr // a missing file just means there is nothing to restore
	}
	servers := info.Servers
	for _, s := range strings.Split(strings.TrimSpace(raw), ",") {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(servers, s) {
			servers = append(servers, s)
		}
	}
	joined := strings.Join(servers, ",")
	if err := client.UpdateDNSConfig(routeros.DNSUpdateConfig{Servers: &joined}); err != nil {
		return err
	}
	return client.DeleteFile(path)
}

// HandleGetDNSLeakGuard reports whether DNS leak protection is on
// @Summary Get DNS Leak Protection
// @Tags DNS
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Produce json
// @Success 200 {object} common.Response{data=DNSLeakGuardResponse}
// @Failure 500 {object} common.Response
// @Router /api/dns/leak-guard [get].
func HandleGetDNSLeakGuard(c echo.Context) error {
	client, err := common.GetRouterOSClient(c)
	if err != nil {
		return err
	}
	enabled, err := dnsLeakGuardEnabled(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to read DNS leak protection", err)
	}
	return common.SuccessResponse(c, http.StatusOK, "DNS leak protection retrieved successfully",
		DNSLeakGuardResponse{Enabled: enabled})
}

// HandleSetDNSLeakGuard turns DNS leak protection on or off
// @Summary Set DNS Leak Protection
// @Description On takes the domestic ISP's resolvers out of the router's DNS servers (remembering them)
// @Description and adds main-table blackhole routes (distance 250) for the remaining resolvers, so when
// @Description their tunnel or foreign route is down queries are dropped instead of leaving through the
// @Description domestic link. Off puts the domestic resolvers back and removes the routes.
// @Tags DNS
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param body body SetDNSLeakGuardRequest true "Desired state"
// @Accept json
// @Produce json
// @Success 200 {object} common.Response{data=DNSLeakGuardResponse}
// @Failure 400 {object} common.Response
// @Failure 500 {object} common.Response
// @Router /api/dns/leak-guard [put].
func HandleSetDNSLeakGuard(c echo.Context) error {
	client, err := common.GetRouterOSClient(c)
	if err != nil {
		return err
	}
	var req SetDNSLeakGuardRequest
	if err := c.Bind(&req); err != nil || req.Enabled == nil {
		return common.ErrorResponse(c, http.StatusBadRequest, "enabled is required", err)
	}

	existing, err := dnsLeakGuardRoutes(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to read DNS leak protection", err)
	}
	have := make(map[string]bool, len(existing))
	for _, r := range existing {
		have[r.DstAddress] = true
		if !*req.Enabled {
			if _, err := client.Remove("/ip/route", "=.id="+r.ID); err != nil {
				return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to remove DNS leak protection", err)
			}
		}
	}
	if *req.Enabled {
		for _, dst := range dnsLeakGuardResolvers {
			if have[dst] {
				continue
			}
			if _, err := client.Add("/ip/route",
				"=dst-address="+dst,
				"=blackhole=yes",
				"=distance=250",
				"=routing-table=main",
				"=comment="+dnsLeakGuardComment,
			); err != nil {
				return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to add DNS leak protection", err)
			}
		}
	}
	if err := setDomesticDNSServers(client, *req.Enabled); err != nil {
		return common.ErrorResponse(c, http.StatusConflict, "Failed to update the router's DNS servers", err)
	}
	return common.SuccessResponse(c, http.StatusOK, "DNS leak protection updated", DNSLeakGuardResponse{Enabled: *req.Enabled})
}
