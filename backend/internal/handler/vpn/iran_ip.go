package vpn

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"nasnet-panel/internal/handler/common"
	"nasnet-panel/internal/handler/plugin"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"nasnet-panel/pkg/routeros"
	"nasnet-panel/pkg/utils"

	"github.com/labstack/echo/v4"
)

// The Split networks send traffic for addresses in DOMAddList out the
// domestic link and everything else through the VPN. The panel can keep that
// list in sync with public Iranian IP lists on GitHub. It downloads and parses
// them itself (the router never imports a script fetched from the internet)
// and applies only the difference.
const (
	iranIPListName = "DOMAddList"
	iranIPComment  = "nasnet-iran-ip"
	// Marks the panel as the list's owner and records the last update; while
	// it exists, the wizard's own updater (DomesticIPUpdate) stays disabled
	// so the two never fight over the list.
	iranIPStateFile = "iran-ip-list-updated.txt"
	// A downloaded list smaller than this is treated as broken rather than
	// as Iran suddenly shrinking.
	iranIPMinPrefixes = 1000
	iranIPMaxBytes    = 4 << 20
	iranIPRefreshAge  = 7 * 24 * time.Hour
)

// iranIPSources are merged: a GeoIP-based list (catches ranges registered
// abroad but used in Iran) and the RIR registry's allocations to Iran.
var iranIPSources = []string{
	"https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/text/ir.txt",
	"https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv4-aggregated.txt",
}

// The wizard's scheduler entries that refresh DOMAddList from its own source.
var legacyIranIPSchedulers = []string{"DomesticIPUpdate", "DomesticIPUpdate-BootCheck"}

// parseIranIPList extracts the public IPv4 prefixes from a list with one
// CIDR (or address) per line, ignoring comments and anything malformed.
func parseIranIPList(body []byte) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		var p netip.Prefix
		var err error
		if strings.Contains(line, "/") {
			p, err = netip.ParsePrefix(line)
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(line); err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil || !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		// Private and shared ranges belong to the LAN and the tunnels, not
		// to the domestic uplink.
		if a := p.Addr(); a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
			a.IsMulticast() || a.IsUnspecified() || netip.MustParsePrefix("100.64.0.0/10").Overlaps(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// mergePrefixes sorts prefixes and drops those contained in another.
func mergePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	sort.Slice(prefixes, func(i, j int) bool {
		if c := prefixes[i].Addr().Compare(prefixes[j].Addr()); c != 0 {
			return c < 0
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	var out []netip.Prefix
	for _, p := range prefixes {
		if n := len(out); n > 0 && out[n-1].Overlaps(p) && out[n-1].Bits() <= p.Bits() {
			continue
		}
		out = append(out, p)
	}
	return out
}

// fetchIranIPList downloads and merges every source. A source that fails is
// skipped as long as the result is still plausibly complete.
func fetchIranIPList(ctx context.Context) ([]netip.Prefix, error) {
	var all []netip.Prefix
	var errs []string
	for _, url := range iranIPSources {
		body, err := httpGetWithRetry(ctx, url, iranIPMaxBytes, nil, nil)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", url, err))
			continue
		}
		all = append(all, parseIranIPList(body)...)
	}
	merged := mergePrefixes(all)
	if len(merged) < iranIPMinPrefixes {
		return nil, fmt.Errorf("only %d prefixes downloaded (%s)", len(merged), strings.Join(errs, "; "))
	}
	return merged, nil
}

// applyIranIPList makes DOMAddList hold exactly prefixes, touching only the
// entries that differ.
func applyIranIPList(client *routeros.Client, prefixes []netip.Prefix) (added, removed int, err error) {
	current, err := client.ListFirewallAddressListItems(routeros.FirewallAddressListFilter{ListName: iranIPListName})
	if err != nil {
		return 0, 0, err
	}
	want := make(map[string]bool, len(prefixes))
	for _, p := range prefixes {
		want[p.String()] = true
	}
	have := make(map[string]bool, len(current))
	var stale []string
	for _, item := range current {
		key := normalizeListAddress(item.Address)
		if want[key] && !have[key] {
			have[key] = true
			continue
		}
		stale = append(stale, item.ID)
	}

	// Add before removing so Iranian destinations never fall out of the
	// list mid-update.
	for _, p := range prefixes {
		if have[p.String()] {
			continue
		}
		if _, err := client.AddFirewallAddressListItem(iranIPListName, p.String(), false, iranIPComment); err != nil {
			return added, removed, fmt.Errorf("failed to add %s: %w", p, err)
		}
		added++
	}
	for _, id := range stale {
		if err := client.RemoveFirewallAddressListItem(id); err != nil {
			return added, removed, err
		}
		removed++
	}
	return added, removed, nil
}

// normalizeListAddress renders RouterOS address-list entries ("1.2.3.0/24",
// "1.2.3.4", or a range) the way prefixes print, so they can be compared.
func normalizeListAddress(addr string) string {
	if p, err := netip.ParsePrefix(addr); err == nil {
		return p.Masked().String()
	}
	if a, err := netip.ParseAddr(addr); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	return addr
}

func iranIPStatePath(client *routeros.Client) string {
	return plugin.StoragePrefix(client) + routeros.NasnetPanelDir + "/" + iranIPStateFile
}

// setLegacyIranIPUpdater enables or disables the wizard's scheduler entries.
func setLegacyIranIPUpdater(client *routeros.Client, enabled bool) error {
	for _, name := range legacyIranIPSchedulers {
		items, err := client.GetAll("/system/scheduler", "?=name="+name)
		if err != nil {
			return err
		}
		for _, item := range items {
			if _, err := client.Set("/system/scheduler", "=.id="+item[".id"], "=disabled="+utils.ToYesNo(!enabled)); err != nil {
				return err
			}
		}
	}
	return nil
}

// updateIranIPList downloads the lists, applies them and records the update.
func updateIranIPList(ctx context.Context, client *routeros.Client) (IranIPUpdateResponse, error) {
	prefixes, err := fetchIranIPList(ctx)
	if err != nil {
		return IranIPUpdateResponse{}, err
	}
	if err := setLegacyIranIPUpdater(client, false); err != nil {
		return IranIPUpdateResponse{}, fmt.Errorf("failed to disable the previous updater: %w", err)
	}
	added, removed, err := applyIranIPList(client, prefixes)
	if err != nil {
		return IranIPUpdateResponse{}, err
	}
	now := time.Now().UTC()
	if err := client.AddFile(iranIPStatePath(client), now.Format(time.RFC3339)); err != nil {
		return IranIPUpdateResponse{}, err
	}
	return IranIPUpdateResponse{Total: len(prefixes), Added: added, Removed: removed, UpdatedAt: now}, nil
}

// iranIPListUpdatedAt returns when the panel last updated the list, or the
// zero time if the panel does not manage it.
func iranIPListUpdatedAt(client *routeros.Client) time.Time {
	raw, err := client.GetFileContents(iranIPStatePath(client), 0)
	if err != nil {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	return t
}

// refreshIranIPListIfDue runs from the background refresher.
func refreshIranIPListIfDue(client *routeros.Client) error {
	updated := iranIPListUpdatedAt(client)
	if updated.IsZero() || time.Since(updated) < iranIPRefreshAge {
		return nil
	}
	_, err := updateIranIPList(context.Background(), client)
	return err
}

// HandleGetIranIPList describes the Iranian IP list used for split routing
// @Summary Get Iranian IP List
// @Description Returns how many entries DOMAddList holds and whether, and when, the panel last updated it
// @Description from its GitHub sources.
// @Tags Route
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Produce json
// @Success 200 {object} common.Response{data=IranIPListResponse}
// @Failure 500 {object} common.Response
// @Router /api/route/iran-ip [get].
func HandleGetIranIPList(c echo.Context) error {
	client, err := common.GetRouterOSClient(c)
	if err != nil {
		return err
	}
	items, err := client.ListFirewallAddressListItems(routeros.FirewallAddressListFilter{ListName: iranIPListName})
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to read the Iranian IP list", err)
	}
	resp := IranIPListResponse{Entries: len(items), Sources: iranIPSources}
	if t := iranIPListUpdatedAt(client); !t.IsZero() {
		resp.ManagedByPanel = true
		resp.UpdatedAt = &t
	}
	return common.SuccessResponse(c, http.StatusOK, "Iranian IP list retrieved successfully", resp)
}

// HandleUpdateIranIPList refreshes the Iranian IP list now
// @Summary Update Iranian IP List
// @Description Downloads the Iranian IP lists from GitHub, merges them and makes DOMAddList match,
// @Description adding before removing. From then on the panel refreshes it weekly and the wizard's
// @Description previous updater stays disabled.
// @Tags Route
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Produce json
// @Success 200 {object} common.Response{data=IranIPUpdateResponse}
// @Failure 502 {object} common.Response
// @Router /api/route/iran-ip/update [post].
func HandleUpdateIranIPList(c echo.Context) error {
	client, err := common.GetRouterOSClient(c)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	resp, err := updateIranIPList(ctx, client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusBadGateway, "Failed to update the Iranian IP list", err)
	}
	ensureV2RayRefresher(c)
	return common.SuccessResponse(c, http.StatusOK, "Iranian IP list updated", resp)
}
