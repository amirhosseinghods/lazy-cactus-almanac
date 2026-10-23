package handler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"nasnet-panel/pkg/proxylink"
	"nasnet-panel/pkg/routeros"
	"nasnet-panel/pkg/sftp"
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

	v2rayNamePrefix = "v2ray-"
	v2rayVethPrefix = "veth-"
	// Setting NASNET_V2RAY_IMAGE makes RouterOS pull that image from a
	// registry instead of loading the trimmed sing-box tar the panel stages
	// (see v2ray_image.go).
	v2rayImageEnv    = "NASNET_V2RAY_IMAGE"
	v2rayConfigDir   = "/etc/sing-box"
	v2raySubnetBase  = "192.168.50."
	v2raySubnetMask  = "/24"
	v2rayGatewayIP   = "192.168.50.1"
	v2rayFirstHostIP = 10

	// Container env keys carrying display metadata, so listing clients needs
	// no extra round trips to read the config file back.
	v2rayEnvProtocol = "NASNET_V2RAY_PROTOCOL"
	v2rayEnvServer   = "NASNET_V2RAY_SERVER"
	v2rayEnvMode     = "NASNET_V2RAY_MODE"

	v2rayModeLink         = "link"
	v2rayModeSubscription = "subscription"

	// The router's CPU and RAM are shared with routing itself, so sing-box is
	// held to one core and a modest heap, with a hard ceiling RouterOS
	// enforces in case the Go runtime overshoots.
	v2rayGoMaxProcs      = "1"
	v2rayGoMemLimit      = "40MiB"
	v2rayMemoryHighBytes = 64 << 20
	v2rayMemoryMaxBytes  = 96 << 20
)

// v2rayRemoteImage returns the registry image to pull when one is
// configured, or "" to load the staged tar.
func v2rayRemoteImage() string {
	return strings.TrimSpace(os.Getenv(v2rayImageEnv))
}

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
	// Bytes of the image downloaded so far and in total (0 when unknown).
	bytesDone, bytesTotal int64
}

func (t *v2rayTask) setProgress(done, total int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bytesDone, t.bytesTotal = done, total
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
	return V2RayClientTaskStatus{
		Name:       name,
		Phase:      t.phase,
		Message:    t.message,
		Done:       t.done,
		Failed:     t.failed,
		BytesDone:  t.bytesDone,
		BytesTotal: t.bytesTotal,
	}
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

	hasLink, hasSubscription := strings.TrimSpace(req.Link) != "", strings.TrimSpace(req.Subscription) != ""
	if hasLink == hasSubscription {
		return ErrorResponse(c, http.StatusBadRequest, "Provide either a share link or a subscription URL", nil)
	}

	// Only cheap checks happen here; downloading the subscription and the
	// image can take minutes, so they run in the background and the UI
	// polls the task for progress.
	d := v2rayDeployment{
		comment:  strings.TrimSpace(req.Comment),
		mode:     v2rayModeLink,
		disabled: req.Disabled != nil && *req.Disabled,
		upload:   v2rayImageUpload{sftp: v2raySFTPConfig(c)},
	}
	if hasSubscription {
		subscriptionURL, err := validateSubscriptionURL(req.Subscription)
		if err != nil {
			return ErrorResponse(c, http.StatusBadRequest, "Invalid subscription URL", err)
		}
		d.mode = v2rayModeSubscription
		d.subscriptionURL = subscriptionURL
	} else {
		link, err := proxylink.Parse(req.Link)
		if err != nil {
			return ErrorResponse(c, http.StatusBadRequest, "Invalid V2Ray link", err)
		}
		if d.comment == "" {
			d.comment = link.Name
		}
		d.links = &proxylink.SubscriptionResult{Links: []*proxylink.Link{link}}
	}

	name := v2rayNamePrefix + utils.GenerateName(2, "-", utils.LowerCase)
	if _, err := client.GetContainer(name); err == nil {
		return ErrorResponse(c, http.StatusConflict, "A V2Ray client with this name already exists, try again", nil)
	}

	task := &v2rayTask{phase: "preparing", message: "preparing"}
	key := v2rayTaskKey(routerHost(c), name)
	v2rayTasks.Lock()
	v2rayTasks.byKey[key] = task
	v2rayTasks.Unlock()

	d.name = name
	go createV2RayClient(client, task, d)

	return SuccessResponse(c, http.StatusAccepted, "V2Ray client creation started", task.snapshot(name))
}

type v2rayDeployment struct {
	upload          v2rayImageUpload
	name            string
	comment         string
	mode            string
	subscriptionURL string
	// links is set up front for a share link and filled in from the
	// subscription otherwise.
	links    *proxylink.SubscriptionResult
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

	// Everything that can fail slowly or for lack of space happens before
	// the router's configuration is touched.
	var meta *v2rayMeta
	if d.mode == v2rayModeSubscription {
		task.set("fetching_subscription", "downloading the subscription")
		res, err := fetchSubscription(context.Background(), d.subscriptionURL)
		if err != nil {
			fail("failed to load the subscription", err)
			return
		}
		secret, err := randomSecret()
		if err != nil {
			fail("failed to generate API secret", err)
			return
		}
		d.links = res
		meta = newV2RayMeta(d.subscriptionURL, secret, res)
	} else {
		meta = newV2RayMeta("", "", d.links)
	}
	config, err := proxylink.GatewayConfig(d.links.Links, proxylink.GatewayOptions{ClashAPISecret: meta.APISecret})
	if err != nil {
		fail("failed to build sing-box configuration", err)
		return
	}

	remoteImage := v2rayRemoteImage()
	imageFile := ""
	if remoteImage == "" {
		task.set("downloading", "downloading sing-box")
		path, err := stageV2RayImage(context.Background(), client, d.upload, d.name, task.setProgress)
		if err != nil {
			fail("failed to prepare the sing-box image", err)
			return
		}
		imageFile = path
		undo = append(undo, func() { _ = client.DeleteFile(imageFile) })
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
	if err := client.AddFile(volumeDir+"/"+v2rayConfigFile, string(config)); err != nil {
		fail("failed to write sing-box configuration", err)
		return
	}
	if err := writeV2RayMeta(client, volumeDir, meta); err != nil {
		fail("failed to write client metadata", err)
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
		RemoteImage: remoteImage,
		File:        imageFile,
		Hostname:    d.name,
		Env: joinEnvPairs(map[string]string{
			v2rayEnvMode:     d.mode,
			v2rayEnvProtocol: meta.Servers[0].Protocol,
			v2rayEnvServer:   meta.Servers[0].Server,
			"GOMAXPROCS":     v2rayGoMaxProcs,
			"GOMEMLIMIT":     v2rayGoMemLimit,
		}),
		MemoryHigh:  v2rayMemoryHighBytes,
		MemoryMax:   v2rayMemoryMaxBytes,
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

	task.set("pulling", "unpacking sing-box")
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
			if imageFile != "" {
				// Unpacked into the container's root dir; the tar would only
				// keep occupying flash.
				_ = client.DeleteFile(imageFile)
			}
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

	mode := v2rayClientEnv(info, v2rayEnvMode)
	protocol := v2rayClientEnv(info, v2rayEnvProtocol)
	server := v2rayClientEnv(info, v2rayEnvServer)
	address, _ := v2rayClientIP(client, info)
	resp := V2RayClientDetailsResponse{
		Name:     info.Name,
		Comment:  info.Comment,
		Mode:     firstNonEmptyString(mode, v2rayModeLink),
		Protocol: protocol,
		Server:   server,
		Address:  address,
		Running:  info.Running,
		Disabled: !info.StartOnBoot,
		Pulling:  info.DownloadingExtracting,
	}
	if meta, err := readV2RayMeta(client, name); err == nil {
		resp.Skipped = meta.Skipped
		resp.RefreshedAt = &meta.RefreshedAt
		var state *v2rayProxyState
		if info.Running {
			state = v2rayProxies(c.Request().Context(), address, meta.APISecret)
		}
		if state != nil {
			resp.Manual = state.Manual
			resp.CanSelect = state.CanSelect && len(meta.Servers) > 1
		}
		for _, s := range meta.Servers {
			server := V2RayServer{
				Name:     s.Name,
				Protocol: s.Protocol,
				Server:   s.Server,
			}
			if state != nil {
				server.Selected = s.Tag == state.Active
				if d, ok := state.Delays[s.Tag]; ok {
					server.DelayMs = &d
				}
			}
			resp.Servers = append(resp.Servers, server)
		}
	}
	return SuccessResponse(c, http.StatusOK, "V2Ray client retrieved successfully", resp)
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
	v2rayAPISecrets.Delete(name)
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
	var ifaces map[string]routeros.InterfaceInfo
	var addresses map[string]string
	for i := range containers {
		info := &containers[i]
		if !isV2RayClientName(info.Name) {
			continue
		}
		if ifaces == nil {
			ifaces = v2rayInterfaceStats(client)
			addresses, _ = client.ListVethAddresses()
		}
		vpn := v2rayVPNClientInfo(info)
		// The veth counters are the client's traffic; seen from the router,
		// what comes back from the container is the download.
		if st, ok := ifaces[info.Interface]; ok {
			if st.RxByte != nil {
				vpn.RxByte = *st.RxByte
			}
			if st.TxByte != nil {
				vpn.TxByte = *st.TxByte
			}
		}
		if info.Running {
			if secret := v2rayAPISecret(client, info.Name); secret != "" {
				if state := v2rayProxies(context.Background(), addresses[info.Interface], secret); state != nil {
					if d, ok := state.Delays[state.Active]; ok {
						vpn.PingTime = fmt.Sprintf("%dms", d)
					}
				}
			}
		}
		clients = append(clients, vpn)
	}
	return clients, nil
}

func v2rayInterfaceStats(client *routeros.Client) map[string]routeros.InterfaceInfo {
	out := map[string]routeros.InterfaceInfo{}
	list, err := client.ListInterfaces()
	if err != nil {
		return out
	}
	for i := range list {
		out[list[i].Name] = list[i]
	}
	return out
}

// v2rayAPISecrets caches each client's Clash API secret, so the clients list
// (polled every few seconds) does not read meta.json from flash each time.
var v2rayAPISecrets sync.Map

func v2rayAPISecret(client *routeros.Client, name string) string {
	if v, ok := v2rayAPISecrets.Load(name); ok {
		if secret, ok := v.(string); ok {
			return secret
		}
	}
	meta, err := readV2RayMeta(client, name)
	if err != nil {
		return ""
	}
	v2rayAPISecrets.Store(name, meta.APISecret)
	return meta.APISecret
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

// v2rayClientEnv reads one of the values recorded in the container's
// environment.
func v2rayClientEnv(info *routeros.ContainerInfo, key string) string {
	for _, pair := range strings.Split(info.Env, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(pair), "=")
		if k == key {
			return v
		}
	}
	return ""
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
	// Routing to a client still downloading, or one that never started,
	// sends the VPN's traffic into a dead end.
	if !info.Running {
		return "", fmt.Errorf("V2Ray client %s is not running yet", gateway)
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

// v2raySFTPConfig reuses the request's router credentials for the SFTP upload
// of the image tar, the same way the setup wizard uploads its script.
func v2raySFTPConfig(c echo.Context) sftp.Config {
	cfg := sftp.Config{Timeout: 2 * time.Minute}
	if creds, err := GetRouterOSCredentials(c); err == nil {
		cfg.Host, cfg.Username, cfg.Password = creds.RouterOSHost, creds.Username, creds.Password
	}
	return cfg
}
