package handler

import (
	"net/http"

	"nasnet-panel/pkg/routeros"

	"github.com/labstack/echo/v4"
)

// The router resolves names through 1.0.0.1 and 1.1.1.1, reached over the
// VPN or the foreign link by host routes that check their gateway. When such
// a route goes down, the query falls through to the next default route,
// which may be the domestic link, whose ISP intercepts port 53 and answers
// itself, revealing what is being looked up. DNS leak protection adds a
// last-resort blackhole for those resolvers, so a failed tunnel makes DNS
// fail instead of leak.
const dnsLeakGuardComment = "nasnet-dns-leak-guard"

// dnsLeakGuardResolvers are the resolvers the NasNet layout routes over the
// tunnel or foreign link.
var dnsLeakGuardResolvers = []string{"1.0.0.1/32", "1.1.1.1/32"}

func dnsLeakGuardRoutes(client *routeros.Client) ([]routeros.IPRouteInfo, error) {
	return client.ListIPRoutesWithFilters(routeros.IPRouteFilter{Comment: dnsLeakGuardComment})
}

// HandleGetDNSLeakGuard reports whether DNS leak protection is on
// @Summary Get DNS Leak Protection
// @Tags DNS
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Produce json
// @Success 200 {object} Response{data=DNSLeakGuardResponse}
// @Failure 500 {object} Response
// @Router /api/dns/leak-guard [get].
func HandleGetDNSLeakGuard(c echo.Context) error {
	client, err := GetRouterOSClient(c)
	if err != nil {
		return err
	}
	routes, err := dnsLeakGuardRoutes(client)
	if err != nil {
		return ErrorResponse(c, http.StatusInternalServerError, "Failed to read DNS leak protection", err)
	}
	return SuccessResponse(c, http.StatusOK, "DNS leak protection retrieved successfully",
		DNSLeakGuardResponse{Enabled: len(routes) >= len(dnsLeakGuardResolvers)})
}

// HandleSetDNSLeakGuard turns DNS leak protection on or off
// @Summary Set DNS Leak Protection
// @Description On adds main-table blackhole routes (distance 250) for the resolvers the router uses, so
// @Description when their tunnel or foreign route is down queries are dropped instead of leaving through
// @Description the domestic link. Off removes them.
// @Tags DNS
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param body body SetDNSLeakGuardRequest true "Desired state"
// @Accept json
// @Produce json
// @Success 200 {object} Response{data=DNSLeakGuardResponse}
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /api/dns/leak-guard [put].
func HandleSetDNSLeakGuard(c echo.Context) error {
	client, err := GetRouterOSClient(c)
	if err != nil {
		return err
	}
	var req SetDNSLeakGuardRequest
	if err := c.Bind(&req); err != nil || req.Enabled == nil {
		return ErrorResponse(c, http.StatusBadRequest, "enabled is required", err)
	}

	existing, err := dnsLeakGuardRoutes(client)
	if err != nil {
		return ErrorResponse(c, http.StatusInternalServerError, "Failed to read DNS leak protection", err)
	}
	have := make(map[string]bool, len(existing))
	for _, r := range existing {
		have[r.DstAddress] = true
		if !*req.Enabled {
			if _, err := client.Remove("/ip/route", "=.id="+r.ID); err != nil {
				return ErrorResponse(c, http.StatusInternalServerError, "Failed to remove DNS leak protection", err)
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
				return ErrorResponse(c, http.StatusInternalServerError, "Failed to add DNS leak protection", err)
			}
		}
	}
	return SuccessResponse(c, http.StatusOK, "DNS leak protection updated", DNSLeakGuardResponse{Enabled: *req.Enabled})
}
