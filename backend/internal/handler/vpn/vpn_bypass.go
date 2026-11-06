package vpn

import (
	"errors"
	"fmt"
	"nasnet-panel/internal/handler/common"
	"nasnet-panel/internal/handler/plugin"
	"net/http"
	"strings"

	"nasnet-panel/pkg/routeros"

	"github.com/labstack/echo/v4"
)

// The VPN bypass is an emergency switch: when the VPN is slow or down, it
// points the VPN routes at the foreign link's own gateway so traffic that
// would go through the tunnel goes straight out the foreign uplink instead.
// The gateway in use before is kept in a file on the router so the switch
// can put it back, even after the panel restarts.
const (
	VPNRoutesComment     = "Route-to-VPN-Client"
	foreignRoutesComment = "Route-to-Foreign-Foreign Link"
	vpnDirectRestoreFile = "vpn-bypass-restore.txt"
)

func vpnDirectRestorePath(client *routeros.Client) string {
	return plugin.StoragePrefix(client) + routeros.NasnetPanelDir + "/" + vpnDirectRestoreFile
}

// ForeignLinkGateway returns the gateway the to-Foreign table sends its
// default route to.
func ForeignLinkGateway(client *routeros.Client) (string, error) {
	routes, err := client.ListIPRoutesWithFilters(routeros.IPRouteFilter{
		Comment:      foreignRoutesComment,
		RoutingTable: "to-Foreign",
		DstAddress:   "0.0.0.0/0",
	})
	if err != nil {
		return "", err
	}
	for _, r := range routes {
		if r.Gateway != "" {
			return r.Gateway, nil
		}
	}
	return "", errors.New("no default route for the foreign link was found")
}

// HandleGetVPNBypass reports whether the VPN bypass is on
// @Summary Get VPN Bypass
// @Description Reports whether VPN traffic currently goes straight out the foreign link instead of
// @Description through a VPN client, and which VPN client turning the bypass off returns to.
// @Tags Route
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Produce json
// @Success 200 {object} common.Response{data=VPNBypassResponse}
// @Failure 500 {object} common.Response
// @Router /api/route/vpn-bypass [get].
func HandleGetVPNBypass(c echo.Context) error {
	client, err := common.GetRouterOSClient(c)
	if err != nil {
		return err
	}
	resp, err := vpnBypassState(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to read VPN bypass state", err)
	}
	return common.SuccessResponse(c, http.StatusOK, "VPN bypass state retrieved successfully", resp)
}

func vpnBypassState(client *routeros.Client) (VPNBypassResponse, error) {
	foreign, err := ForeignLinkGateway(client)
	if err != nil {
		return VPNBypassResponse{}, err
	}
	active, err := activeForeignGateway(client)
	if err != nil {
		return VPNBypassResponse{}, err
	}
	resp := VPNBypassResponse{Enabled: active != "" && active == foreign}
	if resp.Enabled {
		if prev, err := client.GetFileContents(vpnDirectRestorePath(client), 0); err == nil {
			resp.RestoreTo = displayGateway(client, strings.TrimSpace(prev))
		}
	}
	return resp, nil
}

// displayGateway names a route gateway the way the VPN client list does.
func displayGateway(client *routeros.Client, gateway string) string {
	if name := V2RayClientForGateway(client, gateway); name != "" {
		return name
	}
	return gateway
}

// HandleSetVPNBypass turns the VPN bypass on or off
// @Summary Set VPN Bypass
// @Description Turning it on remembers the current VPN gateway and points the VPN routes at the
// @Description foreign link's gateway. Turning it off points them back at the remembered gateway.
// @Description While it is on, traffic meant for the VPN leaves with the foreign link's real IP.
// @Tags Route
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param body body SetVPNBypassRequest true "Desired state"
// @Accept json
// @Produce json
// @Success 200 {object} common.Response{data=VPNBypassResponse}
// @Failure 400 {object} common.Response
// @Failure 409 {object} common.Response
// @Failure 500 {object} common.Response
// @Router /api/route/vpn-bypass [put].
func HandleSetVPNBypass(c echo.Context) error {
	client, err := common.GetRouterOSClient(c)
	if err != nil {
		return err
	}
	var req SetVPNBypassRequest
	if err := c.Bind(&req); err != nil || req.Enabled == nil {
		return common.ErrorResponse(c, http.StatusBadRequest, "enabled is required", err)
	}

	state, err := vpnBypassState(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to read VPN bypass state", err)
	}
	if state.Enabled == *req.Enabled {
		return common.SuccessResponse(c, http.StatusOK, "VPN bypass unchanged", state)
	}

	path := vpnDirectRestorePath(client)
	if *req.Enabled {
		current, err := activeForeignGateway(client)
		if err != nil || current == "" {
			return common.ErrorResponse(c, http.StatusConflict, "No VPN route to bypass was found", err)
		}
		if err := client.AddFile(path, current); err != nil {
			return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to remember the current VPN gateway", err)
		}
		foreign, err := ForeignLinkGateway(client)
		if err != nil {
			return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to find the foreign link gateway", err)
		}
		if err := setVPNRoutesGateway(client, foreign); err != nil {
			return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to bypass the VPN", err)
		}
	} else {
		prev, err := client.GetFileContents(path, 0)
		prev = strings.TrimSpace(prev)
		if err != nil || prev == "" {
			return common.ErrorResponse(c, http.StatusConflict, "The VPN in use before the bypass is unknown; choose a VPN client as the gateway instead", err)
		}
		if err := checkRestorableGateway(client, prev); err != nil {
			return common.ErrorResponse(c, http.StatusConflict, "The VPN in use before the bypass is gone; choose a VPN client as the gateway instead", err)
		}
		if err := setVPNRoutesGateway(client, prev); err != nil {
			return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to restore the VPN", err)
		}
		_ = client.DeleteFile(path)
	}

	state, err = vpnBypassState(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to read VPN bypass state", err)
	}
	return common.SuccessResponse(c, http.StatusOK, "VPN bypass updated", state)
}

// checkRestorableGateway makes sure turning the bypass off would not point
// the VPN routes at something that has since been removed or stopped.
func checkRestorableGateway(client *routeros.Client, gateway string) error {
	if strings.HasSuffix(gateway, "%"+plugin.ContainersBridge) {
		name := V2RayClientForGateway(client, gateway)
		if name == "" {
			return fmt.Errorf("no V2Ray client answers at %s", gateway)
		}
		info, err := client.GetContainer(name)
		if err != nil {
			return err
		}
		if !info.Running {
			return fmt.Errorf("V2Ray client %s is not running", name)
		}
		return nil
	}
	if strings.ContainsAny(gateway, "%.") {
		// An address gateway (such as another uplink); RouterOS checks it.
		return nil
	}
	_, err := client.GetInterface(gateway)
	return err
}

func setVPNRoutesGateway(client *routeros.Client, gateway string) error {
	routes, err := client.ListIPRoutesWithFilters(routeros.IPRouteFilter{Comment: VPNRoutesComment})
	if err != nil {
		return err
	}
	for _, route := range routes {
		if err := client.UpdateIPRoute(route.ID, routeros.IPRouteConfig{Gateway: gateway}); err != nil {
			return err
		}
	}
	return nil
}
