package route

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"nasnet-panel/internal/handler/common"
	"nasnet-panel/internal/handler/vpn"
	"nasnet-panel/pkg/routeros"

	"github.com/labstack/echo/v4"
)

// Iranian sites can be held to VPN clients the user ticks, tried in the
// order given: each gets a default route in their own table, the first
// ticked at distance 1, the next at 2 and so on, so RouterOS moves to the
// next one when a tunnel drops or is deleted. A blackhole behind them
// keeps the sites blocked when none is up. With nothing ticked, the sites
// follow the main VPN gateway (to-VPN) as before.
const (
	iranVPNTable            = "to-Iran-VPN"
	iranVPNRouteComment     = "Iranian sites via VPN: "
	iranVPNBlackholeComment = "Iranian sites blocked when no chosen VPN is up"
	iranVPNBlackholeDist    = "99"
)

// iranVPNRoutes returns the table's default routes that send traffic to a
// VPN, ordered by distance.
func iranVPNRoutes(client *routeros.Client) ([]map[string]string, error) {
	routes, err := client.GetAll("/ip/route", "?=routing-table="+iranVPNTable, "?=dst-address=0.0.0.0/0")
	if err != nil {
		return nil, err
	}
	out := routes[:0]
	for _, r := range routes {
		if !isBlackhole(r) && r["dynamic"] != "true" {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := strconv.Atoi(out[i]["distance"])
		b, _ := strconv.Atoi(out[j]["distance"])
		return a < b
	})
	return out, nil
}

// isBlackhole reports a blackhole route; the API does not always send the
// blackhole flag, but a blackhole is the only default route with no gateway.
func isBlackhole(r map[string]string) bool {
	return r["blackhole"] == "true" || r["gateway"] == ""
}

// routeGateway strips the "%" an interface-only gateway may carry.
func routeGateway(r map[string]string) string {
	return strings.TrimPrefix(r["gateway"], "%")
}

// vpnSitesMark is the routing table the VPN sites rule should point at.
func vpnSitesMark(client *routeros.Client) string {
	if routes, err := iranVPNRoutes(client); err == nil && len(routes) > 0 {
		return iranVPNTable
	}
	return "to-VPN"
}

// HandleListIranSiteVPNs lists the VPN clients Iranian sites may use
// @Summary List VPNs for Iranian Sites
// @Description Every VPN client, with whether hand-added Iranian sites may use it and in which order.
// @Tags Route
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Produce json
// @Success 200 {object} common.Response{data=[]IranSiteVPNResponse}
// @Failure 500 {object} common.Response
// @Router /api/route/foreign-sites/vpns [get].
func HandleListIranSiteVPNs(c echo.Context) error {
	client, err := common.GetRouterOSClient(c)
	if err != nil {
		return err
	}
	list, err := iranSiteVPNs(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to list VPN clients", err)
	}
	return common.SuccessResponse(c, http.StatusOK, "VPN clients retrieved successfully", list)
}

func iranSiteVPNs(client *routeros.Client) ([]IranSiteVPNResponse, error) {
	clients, err := vpn.ListClientGateways(client)
	if err != nil {
		return nil, err
	}
	routes, err := iranVPNRoutes(client)
	if err != nil {
		return nil, err
	}
	out := make([]IranSiteVPNResponse, 0, len(clients))
	for _, cl := range clients {
		item := IranSiteVPNResponse{Name: cl.Name, Label: cl.Label, Type: cl.Type, Running: cl.Running}
		for i, r := range routes {
			if cl.Gateway != "" && routeGateway(r) == cl.Gateway {
				item.Order = i + 1
				// The first ticked tunnel that is up is the one carrying the sites.
				item.InUse = r["active"] == "true"
			}
		}
		out = append(out, item)
	}
	return out, nil
}

// HandleSetIranSiteVPNs sets which VPN clients Iranian sites may use
// @Summary Set VPNs for Iranian Sites
// @Description Ticked VPN clients are tried in the order given; when none is up the sites stay
// @Description blocked. An empty list sends the sites through the main VPN gateway again.
// @Tags Route
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param body body SetIranSiteVPNsRequest true "VPN client names, in order"
// @Accept json
// @Produce json
// @Success 200 {object} common.Response{data=[]IranSiteVPNResponse}
// @Failure 400 {object} common.Response
// @Failure 500 {object} common.Response
// @Router /api/route/foreign-sites/vpns [put].
func HandleSetIranSiteVPNs(c echo.Context) error {
	client, err := common.GetRouterOSClient(c)
	if err != nil {
		return err
	}
	var req SetIranSiteVPNsRequest
	if err := c.Bind(&req); err != nil {
		return common.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}
	clients, err := vpn.ListClientGateways(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to list VPN clients", err)
	}
	gateways := make([]string, 0, len(req.Clients))
	for _, name := range req.Clients {
		gw := ""
		for _, cl := range clients {
			if cl.Name == name {
				gw = cl.Gateway
				if gw == "" {
					return common.ErrorResponse(c, http.StatusBadRequest, name+" is not running yet", errors.New("no gateway"))
				}
			}
		}
		if gw == "" {
			return common.ErrorResponse(c, http.StatusBadRequest, name+" is not a VPN client on this router", errors.New("unknown client"))
		}
		gateways = append(gateways, gw)
	}
	if err := applyIranSiteVPNs(client, req.Clients, gateways); err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to update the VPNs for Iranian sites", err)
	}
	list, err := iranSiteVPNs(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to list VPN clients", err)
	}
	return common.SuccessResponse(c, http.StatusOK, "VPNs for Iranian sites updated", list)
}

func applyIranSiteVPNs(client *routeros.Client, names, gateways []string) error {
	if exists, err := client.RoutingTableExists(iranVPNTable); err != nil {
		return err
	} else if !exists {
		if _, err := client.AddRoutingTable(routeros.RoutingTableConfig{Name: iranVPNTable, FIB: true, Comment: "Iranian sites via chosen VPNs"}); err != nil {
			return err
		}
	}
	all, err := client.GetAll("/ip/route", "?=routing-table="+iranVPNTable)
	if err != nil {
		return err
	}
	hasBlackhole := false
	for _, r := range all {
		if r["dynamic"] == "true" {
			continue
		}
		if isBlackhole(r) {
			hasBlackhole = true
			continue
		}
		if _, err := client.Remove("/ip/route", "=.id="+r[".id"]); err != nil {
			return err
		}
	}
	// The blackhole goes in first, so the table never has a moment with no route at all.
	if !hasBlackhole {
		if _, err := client.Add("/ip/route", "=dst-address=0.0.0.0/0", "=blackhole=yes", "=distance="+iranVPNBlackholeDist,
			"=routing-table="+iranVPNTable, "=comment="+iranVPNBlackholeComment); err != nil {
			return err
		}
	}
	for i, gw := range gateways {
		if _, err := client.Add("/ip/route", "=dst-address=0.0.0.0/0", "=gateway="+gw, "=distance="+strconv.Itoa(i+1),
			"=routing-table="+iranVPNTable, "=comment="+iranVPNRouteComment+names[i]); err != nil {
			return fmt.Errorf("route via %s: %w", names[i], err)
		}
	}
	mark := "to-VPN"
	if len(gateways) > 0 {
		mark = iranVPNTable
	}
	rules, err := client.GetAll("/ip/firewall/mangle", "?=comment="+vpnSitesRuleComment)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if _, err := client.Set("/ip/firewall/mangle", "=.id="+r[".id"], "=new-routing-mark="+mark); err != nil {
			return err
		}
	}
	return nil
}
