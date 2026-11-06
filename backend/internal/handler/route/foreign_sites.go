package route

import (
	"errors"
	"fmt"
	"nasnet-panel/internal/handler/common"
	"nasnet-panel/internal/handler/vpn"
	"net"
	"net/http"
	"regexp"
	"strings"

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
const (
	foreignSitesList        = "Manual-Foreign-Sites"
	foreignSitesRuleComment = "Manual-Sites-via-Foreign"
	// IDs of wildcard rules carry this prefix, since DNS and address-list IDs can collide.
	foreignSitesDNSIDPrefix = "dns"
	// foreignDNSForwarder is the forwarder the base config sends foreign-link lookups to.
	foreignDNSForwarder = "Foreign"
	fallbackDNSServer   = "1.1.1.1"
)

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
	// Domain entries spawn dynamic IP items; show only what the user added.
	items, err := client.GetAll("/ip/firewall/address-list", "?=list="+foreignSitesList, "?=dynamic=false")
	if err != nil {
		return nil, err
	}
	out := make([]ForeignSiteResponse, 0, len(items))
	for _, it := range items {
		out = append(out, ForeignSiteResponse{ID: it[".id"], Address: it["address"]})
	}
	rules, err := listWildcardRules(client)
	if err != nil {
		return nil, err
	}
	return append(out, rules...), nil
}

func listWildcardRules(client *routeros.Client) ([]ForeignSiteResponse, error) {
	entries, err := client.GetAll("/ip/dns/static", "?=address-list="+foreignSitesList)
	if err != nil {
		return nil, err
	}
	out := make([]ForeignSiteResponse, 0, len(entries))
	for _, e := range entries {
		pattern, ok := strings.CutPrefix(e["comment"], foreignSitesRuleComment+": ")
		if !ok {
			continue
		}
		out = append(out, ForeignSiteResponse{ID: foreignSitesDNSIDPrefix + e[".id"], Address: pattern})
	}
	return out, nil
}

func addWildcardRule(client *routeros.Client, pattern string) error {
	forwardTo := fallbackDNSServer
	if fwds, err := client.FindDNSForwarders(routeros.DNSForwarderFilter{Name: foreignDNSForwarder}); err == nil && len(fwds) > 0 {
		forwardTo = foreignDNSForwarder
	}
	_, err := client.Add("/ip/dns/static",
		"=type=FWD",
		"=regexp="+wildcardRegexp(pattern),
		"=forward-to="+forwardTo,
		"=address-list="+foreignSitesList,
		"=comment="+foreignSitesRuleComment+": "+pattern,
	)
	if err != nil {
		return fmt.Errorf("RouterOS 7.6 or newer is needed for wildcard sites: %w", err)
	}
	// Names already in the DNS cache would skip the rule until they expire.
	return client.FlushDNSCache()
}

// ensureForeignSitesRule adds the mangle rule ahead of every other routing
// decision, so the list wins over the VPN, split and domestic rules.
func ensureForeignSitesRule(client *routeros.Client) error {
	rules, err := client.ListMangleRules()
	if err != nil {
		return err
	}
	placeBefore := ""
	for _, r := range rules {
		if r.Comment == foreignSitesRuleComment {
			return nil
		}
		if placeBefore == "" && r.Chain == "prerouting" && r.Action == "mark-routing" {
			placeBefore = r.ID
		}
	}
	_, err = client.AddMangleRule(routeros.MangleRuleConfig{
		Chain:          "prerouting",
		Action:         "mark-routing",
		DstAddressList: foreignSitesList,
		NewRoutingMark: "to-Foreign",
		PlaceBefore:    placeBefore,
		Comment:        foreignSitesRuleComment,
	})
	return err
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
	if err := ensureForeignSitesRule(client); err != nil {
		return common.ErrorResponse(c, http.StatusInternalServerError, "Failed to add the foreign-link routing rule", err)
	}
	if strings.Contains(site, "*") {
		err = addWildcardRule(client, site)
	} else {
		_, err = client.AddFirewallAddressListItem(foreignSitesList, site, false, foreignSitesRuleComment)
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
