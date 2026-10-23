package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"nasnet-panel/pkg/proxylink"
	"nasnet-panel/pkg/routeros"

	"github.com/labstack/echo/v4"
)

const (
	// Subscriptions are re-fetched in the background this often. The
	// container is only restarted when the server list actually changed.
	v2raySubscriptionRefreshInterval = 12 * time.Hour
	v2raySubscriptionFetchTimeout    = 30 * time.Second
	v2raySubscriptionMaxBytes        = 1 << 20
	// Subscription services pick their output format from the User-Agent;
	// a v2rayN-style client gets the portable base64 link list.
	v2raySubscriptionUserAgent = "v2rayN/7.0"

	v2rayMetaFile   = "meta.json"
	v2rayConfigFile = "config.json"
)

// v2rayMeta is what the panel keeps next to a V2Ray client's config on the
// router. It holds the subscription URL and Clash API secret, so like
// config.json it never leaves the router through the API.
type v2rayMeta struct {
	SubscriptionURL string            `json:"subscriptionUrl,omitempty"`
	APISecret       string            `json:"apiSecret,omitempty"`
	Servers         []v2rayMetaServer `json:"servers"`
	Skipped         int               `json:"skipped,omitempty"`
	Truncated       int               `json:"truncated,omitempty"`
	RefreshedAt     time.Time         `json:"refreshedAt"`
}

type v2rayMetaServer struct {
	Tag      string `json:"tag"`
	Name     string `json:"name,omitempty"`
	Protocol string `json:"protocol"`
	Server   string `json:"server"`
}

func newV2RayMeta(subscriptionURL, secret string, res *proxylink.SubscriptionResult) *v2rayMeta {
	meta := &v2rayMeta{
		SubscriptionURL: subscriptionURL,
		APISecret:       secret,
		Skipped:         res.Skipped,
		Truncated:       res.Truncated,
		RefreshedAt:     time.Now().UTC(),
	}
	for i, link := range res.Links {
		tag := proxylink.ProxyTag
		if len(res.Links) > 1 {
			tag = proxylink.ServerTag(i)
		}
		meta.Servers = append(meta.Servers, v2rayMetaServer{
			Tag:      tag,
			Name:     link.Name,
			Protocol: link.Protocol,
			Server:   net.JoinHostPort(link.Server, fmt.Sprint(link.Port)),
		})
	}
	return meta
}

func randomSecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// validateSubscriptionURL accepts only http(s) URLs with a host.
func validateSubscriptionURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("subscription must be an http:// or https:// URL")
	}
	return raw, nil
}

// fetchSubscription downloads and parses a subscription. The request leaves
// through the panel container's own route (the foreign link), so the
// subscription provider sees that link's address.
func fetchSubscription(ctx context.Context, subscriptionURL string) (*proxylink.SubscriptionResult, error) {
	ctx, cancel := context.WithTimeout(ctx, v2raySubscriptionFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subscriptionURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("invalid subscription URL: %w", err)
	}
	req.Header.Set("User-Agent", v2raySubscriptionUserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download subscription: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription server answered %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, v2raySubscriptionMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read subscription: %w", err)
	}
	if len(body) > v2raySubscriptionMaxBytes {
		return nil, fmt.Errorf("subscription is larger than %d bytes", v2raySubscriptionMaxBytes)
	}
	return proxylink.ParseSubscription(body)
}

func v2rayVolumeDir(client *routeros.Client, name string) string {
	return pluginStoragePrefix(client) + routeros.NasnetPanelDir + "/container-volumes/" + name
}

func readV2RayMeta(client *routeros.Client, name string) (*v2rayMeta, error) {
	raw, err := client.GetFileContents(v2rayVolumeDir(client, name)+"/"+v2rayMetaFile, 0)
	if err != nil {
		return nil, err
	}
	var meta v2rayMeta
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", v2rayMetaFile, err)
	}
	return &meta, nil
}

// refreshV2RaySubscription re-fetches a client's subscription and, when the
// resulting config differs, rewrites it and restarts the container. It
// returns whether the config changed.
func refreshV2RaySubscription(ctx context.Context, client *routeros.Client, name string) (*v2rayMeta, bool, error) {
	meta, err := readV2RayMeta(client, name)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read V2Ray client metadata: %w", err)
	}
	if meta.SubscriptionURL == "" {
		return nil, false, errors.New("this V2Ray client was not created from a subscription")
	}

	res, err := fetchSubscription(ctx, meta.SubscriptionURL)
	if err != nil {
		return nil, false, err
	}
	config, err := proxylink.GatewayConfig(res.Links, proxylink.GatewayOptions{ClashAPISecret: meta.APISecret})
	if err != nil {
		return nil, false, err
	}

	dir := v2rayVolumeDir(client, name)
	current, _ := client.GetFileContents(dir+"/"+v2rayConfigFile, 0)
	next := newV2RayMeta(meta.SubscriptionURL, meta.APISecret, res)
	if current == string(config) {
		// Same servers: only record that the refresh happened.
		if err := writeV2RayMeta(client, dir, next); err != nil {
			return nil, false, err
		}
		return next, false, nil
	}

	if err := client.ReplaceFileContents(dir+"/"+v2rayConfigFile, string(config)); err != nil {
		return nil, false, fmt.Errorf("failed to write sing-box configuration: %w", err)
	}
	if err := writeV2RayMeta(client, dir, next); err != nil {
		return nil, false, err
	}

	info, err := client.GetContainer(name)
	if err != nil {
		return nil, true, err
	}
	if info.Running {
		if err := client.StopContainer(name); err != nil {
			return nil, true, fmt.Errorf("failed to stop container: %w", err)
		}
		waitForContainerStop(client, name)
		if err := client.StartContainer(name); err != nil {
			return nil, true, fmt.Errorf("failed to restart container: %w", err)
		}
	}
	return next, true, nil
}

func writeV2RayMeta(client *routeros.Client, dir string, meta *v2rayMeta) error {
	raw, err := json.Marshal(meta) //nolint:gosec // meta.json stays on the router; the secret only guards this client's own sing-box API
	if err != nil {
		return err
	}
	if err := client.AddFile(dir+"/"+v2rayMetaFile, string(raw)); err != nil {
		return fmt.Errorf("failed to write V2Ray client metadata: %w", err)
	}
	return nil
}

// v2rayProxyState is what the container's sing-box reports through its Clash
// API: the last measured delay of each server, the server in use, and
// whether that server was picked by hand.
type v2rayProxyState struct {
	// Delays holds the last urltest delay in milliseconds per server tag; a
	// server that failed its last test is absent.
	Delays map[string]int
	Active string
	Manual bool
	// CanSelect is false for configs written before servers could be picked
	// by hand (the urltest group was the top-level outbound then).
	CanSelect bool
}

func clashAPIRequest(ctx context.Context, method, ip, secret, path string, body io.Reader) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	endpoint := fmt.Sprintf("http://%s%s", net.JoinHostPort(ip, fmt.Sprint(proxylink.ClashAPIPort)), path)
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = cancelOnClose{resp.Body, cancel}
	return resp, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	defer c.cancel()
	return c.ReadCloser.Close()
}

// v2rayProxies reads the container's proxy state. It returns nil when the
// API is off (single-link clients) or unreachable.
func v2rayProxies(ctx context.Context, ip, secret string) *v2rayProxyState {
	if ip == "" || secret == "" {
		return nil
	}
	resp, err := clashAPIRequest(ctx, http.MethodGet, ip, secret, "/proxies", http.NoBody)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Proxies map[string]struct {
			Type    string `json:"type"`
			Now     string `json:"now"`
			History []struct {
				Delay int `json:"delay"`
			} `json:"history"`
		} `json:"proxies"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body) != nil {
		return nil
	}

	state := &v2rayProxyState{Delays: map[string]int{}}
	for tag, p := range body.Proxies {
		if n := len(p.History); n > 0 && p.History[n-1].Delay > 0 {
			state.Delays[tag] = p.History[n-1].Delay
		}
	}
	top := body.Proxies[proxylink.ProxyTag]
	state.Active = top.Now
	if top.Type == "Selector" {
		state.CanSelect = true
		if top.Now == proxylink.AutoTag {
			state.Active = body.Proxies[proxylink.AutoTag].Now
		} else {
			state.Manual = true
		}
	}
	return state
}

// v2raySelect points the container's selector at tag (a server, or AutoTag
// for the fastest one).
func v2raySelect(ctx context.Context, ip, secret, tag string) error {
	payload, err := json.Marshal(map[string]string{"name": tag})
	if err != nil {
		return err
	}
	resp, err := clashAPIRequest(ctx, http.MethodPut, ip, secret, "/proxies/"+proxylink.ProxyTag, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("sing-box refused the selection: %s", strings.TrimSpace(string(msg)))
	}
	return nil
}

// HandleSelectV2RayServer picks a subscription client's server by hand
// @Summary Select V2Ray Server
// @Description Points a subscription client at one of its servers (by index in the details' server list),
// @Description or back to automatic fastest-server selection with "auto". The choice lasts until the
// @Description container restarts, when automatic selection resumes.
// @Tags VPN
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param name path string true "V2Ray client name"
// @Param body body SelectV2RayServerRequest true "Server to use"
// @Accept json
// @Produce json
// @Success 200 {object} Response
// @Failure 400 {object} Response
// @Failure 409 {object} Response
// @Failure 502 {object} Response
// @Router /api/vpn/v2ray/client/{name}/server [put].
func HandleSelectV2RayServer(c echo.Context) error {
	client, err := GetRouterOSClient(c)
	if err != nil {
		return err
	}
	name := c.Param("name")
	if !isV2RayClientName(name) {
		return ErrorResponse(c, http.StatusBadRequest, "Not a V2Ray client name", nil)
	}
	var req SelectV2RayServerRequest
	if err := c.Bind(&req); err != nil {
		return ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}

	info, err := client.GetContainer(name)
	if err != nil {
		return ErrorResponse(c, http.StatusNotFound, "V2Ray client not found", err)
	}
	meta, err := readV2RayMeta(client, name)
	if err != nil || meta.APISecret == "" || len(meta.Servers) < 2 {
		return ErrorResponse(c, http.StatusConflict, "Only subscription clients with several servers can switch servers", err)
	}
	tag := proxylink.AutoTag
	if req.Server != nil {
		if *req.Server < 0 || *req.Server >= len(meta.Servers) {
			return ErrorResponse(c, http.StatusBadRequest, "No server with that index", nil)
		}
		tag = meta.Servers[*req.Server].Tag
	}
	ip, err := v2rayClientIP(client, info)
	if err != nil {
		return ErrorResponse(c, http.StatusInternalServerError, "Failed to find the client's address", err)
	}
	if state := v2rayProxies(c.Request().Context(), ip, meta.APISecret); state != nil && !state.CanSelect {
		return ErrorResponse(c, http.StatusConflict, "This client's configuration predates server selection; press Refresh now once to update it", nil)
	}
	if err := v2raySelect(c.Request().Context(), ip, meta.APISecret, tag); err != nil {
		return ErrorResponse(c, http.StatusBadGateway, "Failed to switch server", err)
	}
	return SimpleSuccessResponse(c, http.StatusOK, "Server selected")
}

// HandleRefreshV2RaySubscription re-fetches a V2Ray client's subscription
// @Summary Refresh V2Ray Subscription
// @Description Downloads the subscription again and, if the server list changed, rewrites the sing-box
// @Description configuration and restarts the client's container.
// @Tags VPN
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param name path string true "V2Ray client name"
// @Produce json
// @Success 200 {object} Response{data=V2RayRefreshResponse}
// @Failure 400 {object} Response
// @Failure 502 {object} Response
// @Router /api/vpn/v2ray/client/{name}/refresh [post].
func HandleRefreshV2RaySubscription(c echo.Context) error {
	client, err := GetRouterOSClient(c)
	if err != nil {
		return err
	}
	name := c.Param("name")
	if !isV2RayClientName(name) {
		return ErrorResponse(c, http.StatusBadRequest, "Not a V2Ray client name", nil)
	}

	meta, changed, err := refreshV2RaySubscription(c.Request().Context(), client, name)
	if err != nil {
		return ErrorResponse(c, http.StatusBadGateway, "Failed to refresh subscription", err)
	}
	return SuccessResponse(c, http.StatusOK, "Subscription refreshed", V2RayRefreshResponse{
		Changed:     changed,
		ServerCount: len(meta.Servers),
		Skipped:     meta.Skipped,
		RefreshedAt: meta.RefreshedAt,
	})
}

// v2rayRefreshers keeps one background subscription refresher per router.
// Like the traffic monitor, it borrows the credentials of the last request
// for that router and only lives in memory: after the panel restarts it
// resumes once the panel is next used.
var v2rayRefreshers = struct {
	sync.Mutex
	byHost map[string]*v2rayRefresher
}{byHost: map[string]*v2rayRefresher{}}

type v2rayRefresher struct {
	mu     sync.Mutex
	config routeros.ConnectionConfig
}

// ensureV2RayRefresher starts the background refresher for the request's
// router, or updates the credentials an existing one uses.
func ensureV2RayRefresher(c echo.Context) {
	creds, err := GetRouterOSCredentials(c)
	if err != nil {
		return
	}
	config := routeros.ConnectionConfig{
		Address:  creds.RouterOSHost,
		Username: creds.Username,
		Password: creds.Password,
	}

	v2rayRefreshers.Lock()
	defer v2rayRefreshers.Unlock()
	if r, ok := v2rayRefreshers.byHost[creds.RouterOSHost]; ok {
		r.mu.Lock()
		r.config = config
		r.mu.Unlock()
		return
	}
	r := &v2rayRefresher{config: config}
	v2rayRefreshers.byHost[creds.RouterOSHost] = r
	go r.run()
}

func (r *v2rayRefresher) run() {
	ticker := time.NewTicker(v2raySubscriptionRefreshInterval)
	defer ticker.Stop()
	for range ticker.C {
		r.mu.Lock()
		config := r.config
		r.mu.Unlock()
		refreshAllV2RaySubscriptions(config)
	}
}

func refreshAllV2RaySubscriptions(config routeros.ConnectionConfig) {
	client, err := routeros.GetOrCreateClient(config)
	if err != nil {
		log.Printf("[v2ray-refresh %s] cannot connect: %v", config.Address, err)
		return
	}
	if err := refreshIranIPListIfDue(client); err != nil {
		log.Printf("[iran-ip-refresh %s] %v", config.Address, err)
	}
	containers, err := client.ListContainers()
	if err != nil {
		log.Printf("[v2ray-refresh %s] cannot list containers: %v", config.Address, err)
		return
	}
	for i := range containers {
		info := &containers[i]
		if !isV2RayClientName(info.Name) {
			continue
		}
		if v2rayClientEnv(info, v2rayEnvMode) != v2rayModeSubscription {
			continue
		}
		// Sequential on purpose: one download and at most one container
		// restart at a time keeps the load on the router low.
		if _, changed, err := refreshV2RaySubscription(context.Background(), client, info.Name); err != nil {
			log.Printf("[v2ray-refresh %s] %s: %v", config.Address, info.Name, err)
		} else if changed {
			log.Printf("[v2ray-refresh %s] %s: server list changed, container restarted", config.Address, info.Name)
		}
	}
}
