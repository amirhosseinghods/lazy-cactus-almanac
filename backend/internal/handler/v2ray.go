package handler

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"nasnet-panel/pkg/proxylink"
	"nasnet-panel/pkg/routeros"
	"nasnet-panel/pkg/utils"

	"github.com/labstack/echo/v4"
)

// V2Ray clients run as sing-box containers on the router's "containers"
// bridge. Each container is a layer-3 gateway: the Route-to-VPN-Client routes
// point at its veth address, and sing-box carries the traffic it receives
// through the proxy described by the share link.
const (
	// VPNTypeV2Ray is the VPN client type reported for V2Ray clients.
	VPNTypeV2Ray = "v2ray"

	v2rayNamePrefix  = "v2ray-"
	v2rayVethPrefix  = "veth-"
	v2rayImage       = "ghcr.io/sagernet/sing-box:v1.14.3"
	v2rayConfigDir   = "/etc/sing-box"
	v2raySubnetBase  = "192.168.50."
	v2raySubnetMask  = "/24"
	v2rayGatewayIP   = "192.168.50.1"
	v2rayFirstHostIP = 10

	// Container env keys carrying display metadata, so listing clients needs
	// no extra round trips to read the config file back.
	v2rayEnvProtocol = "NASNET_V2RAY_PROTOCOL"
	v2rayEnvServer   = "NASNET_V2RAY_SERVER"
)

// v2rayRoutingComment tags the mangle rule that sends a V2Ray container's own
// traffic (to its proxy server) out the foreign link instead of back into the
// VPN routes, which may point at that same container.
func v2rayRoutingComment(name string) string {
	return "V2Ray " + name + " outbound via foreign"
}

func isV2RayClientName(name string) bool {
	return strings.HasPrefix(name, v2rayNamePrefix)
}

// v2rayGateway is the route gateway that sends traffic to a V2Ray container.
// The interface is pinned because the VPN routes live in tables without a
// connected route for the containers subnet.
func v2rayGateway(ip string) string {
	return ip + "%" + pluginContainersBridge
}

// v2rayTask tracks one in-progress V2Ray client creation. Pulling the image
// can take minutes, so creation runs in the background and the UI polls.
type v2rayTask struct {
	mu      sync.RWMutex
	phase   string
	message string
	done    bool
	failed  bool
}

func (t *v2rayTask) set(phase, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.phase, t.message = phase, message
}

func (t *v2rayTask) finish(failed bool, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.done, t.failed, t.message = true, failed, message
	if failed {
		t.phase = "error"
	} else {
		t.phase = "done"
	}
}

func (t *v2rayTask) snapshot(name string) V2RayClientTaskStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return V2RayClientTaskStatus{Name: name, Phase: t.phase, Message: t.message, Done: t.done, Failed: t.failed}
}

var v2rayTasks = struct {
	sync.Mutex
	byKey map[string]*v2rayTask
}{byKey: map[string]*v2rayTask{}}

func v2rayTaskKey(host, name string) string { return host + "|" + name }

// routerHost identifies the router a request targets, so tasks for routers
// managed side by side don't collide.
func routerHost(c echo.Context) string {
	if creds, err := GetRouterOSCredentials(c); err == nil {
		return creds.RouterOSHost
	}
	return ""
}

// HandleAddV2RayClient adds a V2Ray client from a share link
// @Summary Add V2Ray Client
// @Description Parses a vless://, vmess://, trojan://, ss://, hysteria2:// (hy2://) or tuic:// share link
// @Description and deploys it as a sing-box gateway container on the router. The image pull runs in the
// @Description background; poll /api/vpn/v2ray/client/status/{name} until it reports done.
// @Tags VPN
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param request body AddV2RayClientRequest true "V2Ray client configuration"
// @Accept json
// @Produce json
// @Success 202 {object} Response{data=V2RayClientTaskStatus}
// @Failure 400 {object} Response
// @Failure 500 {object} Response
// @Router /api/vpn/v2ray/client [post].
func HandleAddV2RayClient(c echo.Context) error {
	client, err := GetRouterOSClient(c)
	if err != nil {
		return err
	}

	var req AddV2RayClientRequest
	if err := c.Bind(&req); err != nil {
		return ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	link, err := proxylink.Parse(req.Link)
	if err != nil {
		return ErrorResponse(c, http.StatusBadRequest, "Invalid V2Ray link", err)
	}
	config, err := proxylink.GatewayConfig(link)
	if err != nil {
		return ErrorResponse(c, http.StatusInternalServerError, "Failed to build sing-box configuration", err)
	}

	name := v2rayNamePrefix + utils.GenerateName(2, "-", utils.LowerCase)
	if _, err := client.GetContainer(name); err == nil {
		return ErrorResponse(c, http.StatusConflict, "A V2Ray client with this name already exists, try again", nil)
	}

	comment := strings.TrimSpace(req.Comment)
	if comment == "" {
		comment = link.Name
	}

	task := &v2rayTask{phase: "preparing", message: "preparing"}
	key := v2rayTaskKey(routerHost(c), name)
	v2rayTasks.Lock()
	v2rayTasks.byKey[key] = task
	v2rayTasks.Unlock()

	go createV2RayClient(client, task, v2rayDeployment{
		name:     name,
		comment:  comment,
		link:     link,
		config:   string(config),
		disabled: req.Disabled != nil && *req.Disabled,
	})

	return SuccessResponse(c, http.StatusAccepted, "V2Ray client creation started", task.snapshot(name))
}

type v2rayDeployment struct {
	name     string
	comment  string
	link     *proxylink.Link
	config   string
	disabled bool
}

// createV2RayClient provisions everything a V2Ray client needs and rolls back
// whatever it created if a step fails, so a failed attempt leaves no debris.
func createV2RayClient(client *routeros.Client, task *v2rayTask, d v2rayDeployment) {
	var undo []func()
	fail := func(msg string, err error) {
		log.Printf("[v2ray %s] %s: %v", d.name, msg, err)
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		task.finish(true, fmt.Sprintf("%s: %v", msg, err))
	}

	veth := v2rayVethPrefix + d.name
	task.set("creating_interface", "creating interface "+veth)
	ip, err := nextV2RayAddress(client)
	if err != nil {
		fail("failed to allocate an address", err)
		return
	}
	if _, err := client.AddVethInterface(routeros.VethConfig{
		Name:    veth,
		Address: ip + v2raySubnetMask,
		Gateway: v2rayGatewayIP,
	}); err != nil {
		fail("failed to create veth interface", err)
		return
	}
	undo = append(undo, func() { _ = client.RemoveVethInterface(veth) })

	if err := client.AddBridgeMember(pluginContainersBridge, veth, d.name); err != nil {
		fail("failed to add veth interface to the containers bridge", err)
		return
	}

	ruleID, err := client.AddMangleRule(routeros.MangleRuleConfig{
		Chain:          "prerouting",
		Action:         "mark-routing",
		SrcAddr:        ip,
		DstAddressList: "!LOCAL-IP",
		NewRoutingMark: "to-Foreign",
		Comment:        v2rayRoutingComment(d.name),
	})
	if err != nil {
		fail("failed to add routing rule", err)
		return
	}
	undo = append(undo, func() { _ = client.RemoveMangleRule(ruleID) })

	task.set("writing_config", "writing sing-box configuration")
	volumeDir, err := preparePluginVolumeDir(client, d.name, "")
	if err != nil {
		fail("failed to prepare configuration directory", err)
		return
	}
	undo = append(undo, func() { _, _ = removePluginVolumeDir(client, d.name) })
	if err := client.AddFile(volumeDir+"/config.json", d.config); err != nil {
		fail("failed to write sing-box configuration", err)
		return
	}
	if err := client.AddFile(volumeDir+"/entry.sh", proxylink.GatewayEntrypoint); err != nil {
		fail("failed to write container entrypoint", err)
		return
	}
	if _, err := client.AddContainerMount(d.name, volumeDir, v2rayConfigDir); err != nil {
		fail("failed to create container mount", err)
		return
	}
	undo = append(undo, func() { _ = client.RemoveContainerMount(d.name) })

	task.set("creating_container", "creating container "+d.name)
	rootDir, err := preparePluginRootDir(client, d.name)
	if err != nil {
		fail("failed to prepare container directory", err)
		return
	}
	if _, err := client.AddContainer(routeros.ContainerConfig{
		Name:        d.name,
		Interface:   veth,
		RootDir:     rootDir,
		RemoteImage: v2rayImage,
		Hostname:    d.name,
		Env: joinEnvPairs(map[string]string{
			v2rayEnvProtocol: d.link.Protocol,
			v2rayEnvServer:   net.JoinHostPort(d.link.Server, fmt.Sprint(d.link.Port)),
		}),
		MountLists:  d.name,
		Entrypoint:  "/bin/sh",
		Cmd:         v2rayConfigDir + "/entry.sh",
		Logging:     true,
		StartOnBoot: !d.disabled,
		Comment:     d.comment,
	}); err != nil {
		fail("failed to create container", err)
		return
	}
	undo = append(undo, func() { _ = client.RemoveContainer(d.name) })

	task.set("pulling", "downloading "+v2rayImage)
	deadline := time.Now().Add(pluginInstallTimeout)
	for {
		info, err := client.GetContainer(d.name)
		if err != nil {
			fail("lost track of container during download", err)
			return
		}
		if info.DownloadExtractFailed {
			fail("image download failed", fmt.Errorf("%s", firstNonEmptyString(info.About, "unknown error")))
			return
		}
		if !info.DownloadingExtracting {
			break
		}
		if time.Now().After(deadline) {
			fail("timed out downloading the image", fmt.Errorf("still downloading after %s", pluginInstallTimeout))
			return
		}
		time.Sleep(pluginInstallPollInterval)
	}

	if !d.disabled {
		task.set("starting", "starting container "+d.name)
		if err := client.StartContainer(d.name); err != nil {
			fail("failed to start container", err)
			return
		}
	}

	task.finish(false, "V2Ray client ready")
}

// nextV2RayAddress returns the first free host address on the containers
// subnet, starting above the addresses the installer and plugins use.
func nextV2RayAddress(client *routeros.Client) (string, error) {
	used, err := client.ListVethAddresses()
	if err != nil {
		return "", err
	}
	taken := make(map[string]bool, len(used))
	for _, ip := range used {
		taken[ip] = true
	}
	for host := v2rayFirstHostIP; host < 255; host++ {
		ip := fmt.Sprintf("%s%d", v2raySubnetBase, host)
		if !taken[ip] {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no free address left on %s0%s", v2raySubnetBase, v2raySubnetMask)
}

// HandleGetV2RayClientStatus reports the progress of a V2Ray client creation
// @Summary Get V2Ray Client Creation Status
// @Description Returns the current phase of a V2Ray client creation started by POST /api/vpn/v2ray/client.
// @Tags VPN
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param name path string true "V2Ray client name"
// @Produce json
// @Success 200 {object} Response{data=V2RayClientTaskStatus}
// @Failure 404 {object} Response
// @Router /api/vpn/v2ray/client/status/{name} [get].
func HandleGetV2RayClientStatus(c echo.Context) error {
	if _, err := GetRouterOSClient(c); err != nil {
		return err
	}
	name := c.Param("name")

	v2rayTasks.Lock()
	task := v2rayTasks.byKey[v2rayTaskKey(routerHost(c), name)]
	v2rayTasks.Unlock()
	if task == nil {
		return ErrorResponse(c, http.StatusNotFound, "No V2Ray client creation in progress with this name", nil)
	}

	return SuccessResponse(c, http.StatusOK, "V2Ray client creation status", task.snapshot(name))
}

// HandleGetV2RayClient gets a V2Ray client's details
// @Summary Get V2Ray Client
// @Description Returns a V2Ray client's protocol, server and container state. Link secrets are never returned.
// @Tags VPN
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param name path string true "V2Ray client name"
// @Produce json
// @Success 200 {object} Response{data=V2RayClientDetailsResponse}
// @Failure 404 {object} Response
// @Router /api/vpn/v2ray/client/{name} [get].
func HandleGetV2RayClient(c echo.Context) error {
	client, err := GetRouterOSClient(c)
	if err != nil {
		return err
	}

	name := c.Param("name")
	if !isV2RayClientName(name) {
		return ErrorResponse(c, http.StatusBadRequest, "Not a V2Ray client name", nil)
	}
	info, err := client.GetContainer(name)
	if err != nil {
		return ErrorResponse(c, http.StatusNotFound, "V2Ray client not found", err)
	}

	protocol, server := v2rayClientMetadata(info)
	address, _ := v2rayClientIP(client, info)
	return SuccessResponse(c, http.StatusOK, "V2Ray client retrieved successfully", V2RayClientDetailsResponse{
		Name:     info.Name,
		Comment:  info.Comment,
		Protocol: protocol,
		Server:   server,
		Address:  address,
		Running:  info.Running,
		Disabled: !info.StartOnBoot,
		Pulling:  info.DownloadingExtracting,
	})
}

// HandleDeleteV2RayClient removes a V2Ray client
// @Summary Delete V2Ray Client
// @Description Stops and removes a V2Ray client's container together with its interface, mount,
// @Description configuration files and routing rule. Refuses while the client is the active VPN gateway.
// @Tags VPN
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param name path string true "V2Ray client name"
// @Produce json
// @Success 200 {object} Response
// @Failure 404 {object} Response
// @Failure 409 {object} Response
// @Failure 500 {object} Response
// @Router /api/vpn/v2ray/client/{name} [delete].
func HandleDeleteV2RayClient(c echo.Context) error {
	client, err := GetRouterOSClient(c)
	if err != nil {
		return err
	}

	name := c.Param("name")
	if !isV2RayClientName(name) {
		return ErrorResponse(c, http.StatusBadRequest, "Not a V2Ray client name", nil)
	}
	info, err := client.GetContainer(name)
	if err != nil {
		return ErrorResponse(c, http.StatusNotFound, "V2Ray client not found", err)
	}

	if ip, err := v2rayClientIP(client, info); err == nil {
		active, err := activeForeignGateway(client)
		if err != nil {
			return ErrorResponse(c, http.StatusInternalServerError, "Failed to check the active VPN gateway", err)
		}
		if active == v2rayGateway(ip) {
			return ErrorResponse(c, http.StatusConflict, "This V2Ray client is the active VPN; select another VPN before deleting it", nil)
		}
	}

	if info.Running {
		if err := client.StopContainer(name); err != nil {
			return ErrorResponse(c, http.StatusInternalServerError, "Failed to stop container", err)
		}
		waitForContainerStop(client, name)
	}
	if err := client.RemoveContainer(name); err != nil {
		return ErrorResponse(c, http.StatusInternalServerError, "Failed to remove container", err)
	}

	// The container is gone; everything below is best-effort cleanup.
	if err := client.RemoveContainerMount(name); err != nil {
		c.Logger().Errorf("Failed to remove mount %s: %v", name, err)
	}
	if _, err := removePluginVolumeDir(client, name); err != nil {
		c.Logger().Errorf("Failed to remove configuration directory of %s: %v", name, err)
	}
	if id, err := client.GetMangleRuleIDByComment(v2rayRoutingComment(name)); err == nil {
		if err := client.RemoveMangleRule(id); err != nil {
			c.Logger().Errorf("Failed to remove routing rule of %s: %v", name, err)
		}
	}
	if info.Interface != "" {
		if err := client.RemoveVethInterface(info.Interface); err != nil {
			c.Logger().Errorf("Failed to remove interface %s: %v", info.Interface, err)
		}
	}

	return SimpleSuccessResponse(c, http.StatusOK, "V2Ray client deleted successfully")
}

func waitForContainerStop(client *routeros.Client, name string) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		info, err := client.GetContainer(name)
		if err != nil || info.Stopped || !info.Running {
			return
		}
		time.Sleep(time.Second)
	}
}

// listV2RayClients returns the V2Ray client containers as VPN clients.
func listV2RayClients(client *routeros.Client) ([]routeros.VPNClientInfo, error) {
	containers, err := client.ListContainers()
	if err != nil {
		return nil, err
	}

	var clients []routeros.VPNClientInfo
	for i := range containers {
		info := &containers[i]
		if !isV2RayClientName(info.Name) {
			continue
		}
		clients = append(clients, v2rayVPNClientInfo(info))
	}
	return clients, nil
}

func v2rayVPNClientInfo(info *routeros.ContainerInfo) routeros.VPNClientInfo {
	return routeros.VPNClientInfo{
		ID:       info.ID,
		Name:     info.Name,
		Type:     VPNTypeV2Ray,
		Running:  info.Running,
		Disabled: !info.StartOnBoot,
		Comment:  info.Comment,
	}
}

// v2rayClientMetadata reads the protocol and server recorded in the
// container's environment.
func v2rayClientMetadata(info *routeros.ContainerInfo) (protocol, server string) {
	for _, pair := range strings.Split(info.Env, ",") {
		key, value, _ := strings.Cut(strings.TrimSpace(pair), "=")
		switch key {
		case v2rayEnvProtocol:
			protocol = value
		case v2rayEnvServer:
			server = value
		}
	}
	return protocol, server
}

func v2rayClientIP(client *routeros.Client, info *routeros.ContainerInfo) (string, error) {
	addresses, err := client.ListVethAddresses()
	if err != nil {
		return "", err
	}
	ip, ok := addresses[info.Interface]
	if !ok {
		return "", fmt.Errorf("interface %s has no address", info.Interface)
	}
	return ip, nil
}

// setV2RayClientEnabled starts or stops a V2Ray client's container and keeps
// start-on-boot in step, so a disabled client stays down after a reboot.
func setV2RayClientEnabled(client *routeros.Client, name string, enabled bool) error {
	info, err := client.GetContainer(name)
	if err != nil {
		return err
	}
	if err := client.EditContainer(name, map[string]string{"start-on-boot": utils.ToYesNo(enabled)}); err != nil {
		return err
	}
	switch {
	case enabled && !info.Running:
		return client.StartContainer(name)
	case !enabled && info.Running:
		return client.StopContainer(name)
	}
	return nil
}

// updateV2RayClient applies a PUT /api/vpn/clients/{name} request to a V2Ray
// client, whose "interface" is a container rather than a RouterOS interface.
func updateV2RayClient(c echo.Context, client *routeros.Client, name string, req UpdateVPNClientRequest) error {
	if req.Disabled != nil {
		if err := setV2RayClientEnabled(client, name, !*req.Disabled); err != nil {
			return ErrorResponse(c, http.StatusInternalServerError, "Failed to update V2Ray client", err)
		}
	}
	if req.Comment != nil {
		if err := client.EditContainer(name, map[string]string{"comment": *req.Comment}); err != nil {
			return ErrorResponse(c, http.StatusInternalServerError, "Failed to update V2Ray client", err)
		}
	}

	info, err := client.GetContainer(name)
	if err != nil {
		return ErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve updated V2Ray client", err)
	}
	vpn := v2rayVPNClientInfo(info)
	if req.Disabled != nil {
		// Start/stop is asynchronous; report the requested state rather than
		// the container's state a moment before it changes.
		vpn.Running = !*req.Disabled
	}
	return SuccessResponse(c, http.StatusOK, "VPN client updated successfully", ToVPNClientResponse(&vpn))
}

// resolveV2RayGateway maps a V2Ray client name to the route gateway that
// reaches its container. Other names are returned unchanged.
func resolveV2RayGateway(client *routeros.Client, gateway string) (string, error) {
	if !isV2RayClientName(gateway) {
		return gateway, nil
	}
	info, err := client.GetContainer(gateway)
	if err != nil {
		return "", fmt.Errorf("V2Ray client %s not found: %w", gateway, err)
	}
	ip, err := v2rayClientIP(client, info)
	if err != nil {
		return "", err
	}
	return v2rayGateway(ip), nil
}

// v2rayClientForGateway maps a route gateway back to the V2Ray client whose
// container it reaches, or returns "" when it reaches none.
func v2rayClientForGateway(client *routeros.Client, gateway string) string {
	ip, iface, ok := strings.Cut(gateway, "%")
	if !ok || iface != pluginContainersBridge || !strings.HasPrefix(ip, v2raySubnetBase) {
		return ""
	}
	addresses, err := client.ListVethAddresses()
	if err != nil {
		return ""
	}
	for veth, addr := range addresses {
		if addr == ip && strings.HasPrefix(veth, v2rayVethPrefix+v2rayNamePrefix) {
			return strings.TrimPrefix(veth, v2rayVethPrefix)
		}
	}
	return ""
}

func activeForeignGateway(client *routeros.Client) (string, error) {
	routes, err := client.ListIPRoutesWithFilters(routeros.IPRouteFilter{
		Comment:      "Route-to-VPN-Client",
		RoutingTable: "main",
	})
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", nil
	}
	return routes[0].Gateway, nil
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
