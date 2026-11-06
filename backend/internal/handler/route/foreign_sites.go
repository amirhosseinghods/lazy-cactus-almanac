package route

import (
	"context"
	"errors"
	"fmt"
	"log"
	"nasnet-panel/internal/handler/common"
	"nasnet-panel/internal/handler/firewall"
	"nasnet-panel/internal/handler/plugin"
	"nasnet-panel/internal/handler/vpn"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"nasnet-panel/pkg/routeros"

	"github.com/labstack/echo/v4"
)

// Sites the user adds by hand always leave through the foreign link
// (Starlink), whatever network the device is on. RouterOS resolves plain
// domain entries in the address list itself and keeps their IPs current.
//
// Wildcard patterns (*.example.com, star*.example.com, example.*) cannot live
// in an address list, so each becomes a DNS forward rule instead: when a
// device looks up a matching name through the router, RouterOS adds the
// answer's IPs to the same address list. This only covers devices that use
// the router as their DNS server.
//
// A site whose server is in Iran goes through the VPN instead, into its own
// list. The firewall drops traffic to Iranian IPs outside the domestic link
// so an Iranian server never sees the Starlink IP; an accept rule ahead of
// that drop lets this list out through VPN interfaces only, so when the VPN
// is down or bypassed the site stays blocked rather than leaving via Starlink.
const (
	foreignSitesList        = "Manual-Foreign-Sites"
	foreignSitesRuleComment = "Manual-Sites-via-Foreign"
	// IDs of wildcard rules carry this prefix, since DNS and address-list IDs can collide.
	foreignSitesDNSIDPrefix = "dns"
	// foreignDNSForwarder is the forwarder the base config sends foreign-link lookups to.
	foreignDNSForwarder = "Foreign"
	fallbackDNSServer   = "1.1.1.1"

	vpnSitesList        = "Manual-VPN-Sites"
	vpnSitesRuleComment = "Manual-Sites-via-VPN"

	routeStarlink = "starlink"
	routeVPN      = "vpn"
)

// siteRoute is one way out for hand-added sites: its address list, the
// comment its rules carry, and the routing table the mangle rule picks.
type siteRoute struct {
	name, list, comment, mark string
}

var siteRoutes = []siteRoute{
	{routeStarlink, foreignSitesList, foreignSitesRuleComment, "to-Foreign"},
	{routeVPN, vpnSitesList, vpnSitesRuleComment, "to-VPN"},
}

var (
	hostnamePattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	wildcardLabel   = regexp.MustCompile(`^[a-z0-9*-]{1,63}$`)
)

// normalizeSite turns an IPv4 address, range, domain, wildcard pattern or
// pasted URL into a list value, or returns "" when it is none of those.
func normalizeSite(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if ip, _, err := net.ParseCIDR(s); err == nil && ip.To4() != nil {
		return s
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.TrimSuffix(s, ".")
	if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
		return s
	}
	if strings.Contains(s, "*") {
		if validWildcard(s) {
			return s
		}
		return ""
	}
	if hostnamePattern.MatchString(s) {
		return s
	}
	return ""
}

// validWildcard accepts dotted patterns with at least two labels, one of
// which has no wildcard, so "*" or "*.*" cannot send everything to Starlink.
func validWildcard(s string) bool {
	labels := strings.Split(s, ".")
	if len(labels) < 2 || strings.Contains(s, "**") {
		return false
	}
	plain := false
	for _, l := range labels {
		if !wildcardLabel.MatchString(l) {
			return false
		}
		plain = plain || !strings.Contains(l, "*")
	}
	return plain
}

// wildcardRegexp turns a pattern into the regexp RouterOS matches names with.
// A leading "*." also matches the bare domain and any depth of subdomain, a
// trailing ".*" matches any ending (com, co.uk), and "*" inside a label
// matches part of that label.
func wildcardRegexp(pattern string) string {
	labels := strings.Split(pattern, ".")
	prefix, suffix := "", ""
	if labels[0] == "*" {
		prefix, labels = `(.+\.)?`, labels[1:]
	}
	if len(labels) > 0 && labels[len(labels)-1] == "*" {
		suffix, labels = `\..+`, labels[:len(labels)-1]
	}
	for i, l := range labels {
		labels[i] = strings.ReplaceAll(regexp.QuoteMeta(l), `\*`, `[^.]*`)
	}
	return "^" + prefix + strings.Join(labels, `\.`) + suffix + "$"
}

func listForeignSites(client *routeros.Client) ([]ForeignSiteResponse, error) {
	// Domain entries spawn dynamic IP items, commented with the domain; they
	// are not shown, only used to tell which sites resolve to Iranian IPs.
	resolved := map[string][]string{}
	out := []ForeignSiteResponse{}
	for _, r := range siteRoutes {
		items, err := client.GetAll("/ip/firewall/address-list", "?=list="+r.list)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			if it["dynamic"] == "true" {
				resolved[it["comment"]] = append(resolved[it["comment"]], it["address"])
				continue
			}
			out = append(out, ForeignSiteResponse{ID: it[".id"], Address: it["address"], Route: r.name})
		}
		rules, err := listWildcardRules(client, r)
		if err != nil {
			return nil, err
		}
		out = append(out, rules...)
	}
	flagIranianSites(client, out, resolved)
	return out, nil
}

// flagIranianSites fills IranianIPs for sites whose addresses are on the
// Iranian IP list. A failure here only loses the flag, so it is logged.
func flagIranianSites(client *routeros.Client, sites []ForeignSiteResponse, resolved map[string][]string) {
	iran, err := iranianList(client)
	if err != nil {
		log.Printf("foreign sites: cannot read %s: %v", firewall.DomesticAddressList, err)
		return
	}
	for i := range sites {
		sites[i].IranianIPs = iranianAddresses(iran, siteAddresses(sites[i].Address, resolved))
	}
}

func iranianList(client *routeros.Client) ([]routeros.FirewallAddressListItem, error) {
	return client.ListFirewallAddressListItems(routeros.FirewallAddressListFilter{ListName: firewall.DomesticAddressList})
}

func iranianAddresses(iran []routeros.FirewallAddressListItem, addrs []string) []string {
	var out []string
	for _, addr := range addrs {
		// shortcut: a range is flagged only when one Iranian entry holds all of it.
		if m, err := routeros.FilterAddressListByContainment(iran, addr); err == nil && len(m) > 0 {
			out = append(out, addr)
		}
	}
	return out
}

// siteAddresses returns the IPs a site stands for: itself for an address or
// range, the router's resolved entries for a domain, and for a wildcard the
// IPs of its base name (*.example.com -> example.com), when there is one.
func siteAddresses(site string, resolved map[string][]string) []string {
	if net.ParseIP(site) != nil || strings.Contains(site, "/") {
		return []string{site}
	}
	name := strings.TrimPrefix(site, "*.")
	if strings.Contains(name, "*") {
		return nil
	}
	if ips := resolved[name]; len(ips) > 0 {
		return ips
	}
	// A just-added domain has no resolved entries yet.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func listWildcardRules(client *routeros.Client, r siteRoute) ([]ForeignSiteResponse, error) {
	entries, err := client.GetAll("/ip/dns/static", "?=address-list="+r.list)
	if err != nil {
		return nil, err
	}
	out := make([]ForeignSiteResponse, 0, len(entries))
	for _, e := range entries {
		pattern, ok := strings.CutPrefix(e["comment"], r.comment+": ")
		if !ok {
			continue
		}
		out = append(out, ForeignSiteResponse{ID: foreignSitesDNSIDPrefix + e[".id"], Address: pattern, Route: r.name})
	}
	return out, nil
}

func addWildcardRule(client *routeros.Client, r siteRoute, pattern string) error {
	forwardTo := fallbackDNSServer
	if fwds, err := client.FindDNSForwarders(routeros.DNSForwarderFilter{Name: foreignDNSForwarder}); err == nil && len(fwds) > 0 {
		forwardTo = foreignDNSForwarder
	}
	_, err := client.Add("/ip/dns/static",
		"=type=FWD",
		"=regexp="+wildcardRegexp(pattern),
		"=forward-to="+forwardTo,
		"=address-list="+r.list,
		"=comment="+r.comment+": "+pattern,
	)
	if err != nil {
		return fmt.Errorf("RouterOS 7.6 or newer is needed for wildcard sites: %w", err)
	}
	// Names already in the DNS cache would skip the rule until they expire.
	return client.FlushDNSCache()
}

// ensureSitesRule adds the route's mangle rule ahead of every other routing
// decision, so the list wins over the VPN, split and domestic rules.
func ensureSitesRule(client *routeros.Client, r siteRoute) error {
	rules, err := client.ListMangleRules()
	if err != nil {
		return err
	}
	placeBefore := ""
	for _, m := range rules {
		if m.Comment == r.comment {
			return nil
		}
		if placeBefore == "" && m.Chain == "prerouting" && m.Action == "mark-routing" {
			placeBefore = m.ID
		}
	}
	_, err = client.AddMangleRule(routeros.MangleRuleConfig{
		Chain:          "prerouting",
		Action:         "mark-routing",
		DstAddressList: r.list,
		NewRoutingMark: r.mark,
		PlaceBefore:    placeBefore,
		Comment:        r.comment,
	})
	return err
}

// ensureVPNSitesFilter lets the VPN list past the drop of Iranian IPs, but
// only out VPN interfaces: VPN-WAN members and the containers bridge that
// V2Ray clients answer on. It goes right before that drop rule.
func ensureVPNSitesFilter(client *routeros.Client) error {
	existing, err := client.GetAll("/ip/firewall/filter", "?=comment="+vpnSitesRuleComment)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil
	}
	drops, err := client.GetAll("/ip/firewall/filter", "?=chain=forward", "?=action=drop", "?=dst-address-list="+firewall.DomesticAddressList)
	if err != nil {
		return err
	}
	place := []string{}
	if len(drops) > 0 {
		place = append(place, "=place-before="+drops[0][".id"])
	}
	for _, out := range []string{"=out-interface-list=VPN-WAN", "=out-interface=" + plugin.ContainersBridge} {
		args := append([]string{"=chain=forward", "=action=accept", "=dst-address-list=" + vpnSitesList, out, "=comment=" + vpnSitesRuleComment}, place...)
		if _, err := client.Add("/ip/firewall/filter", args...); err != nil {
			return err
		}
	}
	return nil
}

// routeForSite picks the VPN for a site whose server is in Iran, Starlink otherwise.
func routeForSite(client *routeros.Client, site string) siteRoute {
	iran, err := iranianList(client)
	if err == nil && len(iranianAddresses(iran, siteAddresses(site, nil))) > 0 {
		return siteRoutes[1]
	}
	return siteRoutes[0]
}

// HandleListForeignSites lists the sites sent through the foreign link
// @Summary List Foreign-Link Sites
// @Description Sites (domains, IPs or ranges) added by hand that always use the foreign link (Starlink).
// @Tags Route
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Produce json
// @Success 200 {object} common.Response{data=[]ForeignSiteResponse}
// @Failure 500 {object} common.Response
// @Router /api/route/foreign-sites [get].
func HandleListForeignSites(c echo.Context) error {
	client, err := common.GetRouterOSClient(c)
	if err != nil {
		return err
	}
	sites, err := listForeignSites(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to list foreign-link sites", err)
	}
	return common.SuccessResponse(c, http.StatusOK, "Foreign-link sites retrieved successfully", sites)
}

// HandleAddForeignSite adds a site to the foreign-link list
// @Summary Add Foreign-Link Site
// @Description Adds a domain, wildcard pattern (*.example.com, example.*), IPv4 address or range whose traffic always leaves through the foreign link.
// @Tags Route
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param body body AddForeignSiteRequest true "Site"
// @Accept json
// @Produce json
// @Success 201 {object} common.Response{data=[]ForeignSiteResponse}
// @Failure 400 {object} common.Response
// @Failure 409 {object} common.Response
// @Failure 500 {object} common.Response
// @Router /api/route/foreign-sites [post].
func HandleAddForeignSite(c echo.Context) error {
	client, err := common.GetRouterOSClient(c)
	if err != nil {
		return err
	}
	var req AddForeignSiteRequest
	if err := c.Bind(&req); err != nil {
		return common.ErrorResponse(c, http.StatusBadRequest, "Invalid request body", err)
	}
	site := normalizeSite(req.Address)
	if site == "" {
		return common.ErrorResponse(c, http.StatusBadRequest, "Enter a domain (example.com), a wildcard (*.example.com), an IPv4 address or a range", errors.New("invalid site"))
	}
	if _, err := vpn.ForeignLinkGateway(client); err != nil {
		return common.ErrorResponse(c, http.StatusConflict, "This router has no foreign link to send sites through", err)
	}
	existing, err := listForeignSites(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to list foreign-link sites", err)
	}
	for _, s := range existing {
		if s.Address == site {
			return common.ErrorResponse(c, http.StatusConflict, site+" is already in the list", errors.New("duplicate site"))
		}
	}
	r := routeForSite(client, site)
	if err := ensureSitesRule(client, r); err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to add the site routing rule", err)
	}
	if r.name == routeVPN {
		if err := ensureVPNSitesFilter(client); err != nil {
			return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to add the VPN site firewall rule", err)
		}
	}
	if strings.Contains(site, "*") {
		err = addWildcardRule(client, r, site)
	} else {
		_, err = client.AddFirewallAddressListItem(r.list, site, false, r.comment)
	}
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to add "+site, err)
	}
	sites, err := listForeignSites(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to list foreign-link sites", err)
	}
	return common.SuccessResponse(c, http.StatusCreated, "Site added", sites)
}

// HandleRemoveForeignSite removes a site from the foreign-link list
// @Summary Remove Foreign-Link Site
// @Tags Route
// @Security BasicAuth
// @Param X-RouterOS-Host header string true "RouterOS host address"
// @Param id path string true "Address-list item ID"
// @Produce json
// @Success 200 {object} common.Response{data=[]ForeignSiteResponse}
// @Failure 404 {object} common.Response
// @Failure 500 {object} common.Response
// @Router /api/route/foreign-sites/{id} [delete].
func HandleRemoveForeignSite(c echo.Context) error {
	client, err := common.GetRouterOSClient(c)
	if err != nil {
		return err
	}
	id := c.Param("id")
	sites, err := listForeignSites(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to list foreign-link sites", err)
	}
	found := false
	for _, s := range sites {
		found = found || s.ID == id
	}
	// Only items of this list may be removed through this endpoint.
	if !found {
		return common.ErrorResponse(c, http.StatusNotFound, "Site not found", errors.New("unknown id"))
	}
	if dnsID, ok := strings.CutPrefix(id, foreignSitesDNSIDPrefix); ok {
		_, err = client.Remove("/ip/dns/static", "=.id="+dnsID)
	} else {
		err = client.RemoveFirewallAddressListItem(id)
	}
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to remove the site", err)
	}
	sites, err = listForeignSites(client)
	if err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to list foreign-link sites", err)
	}
	return common.SuccessResponse(c, http.StatusOK, "Site removed", sites)
}
