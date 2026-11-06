// Package route holds the route API group handlers.
package route

// UpdateForeignGatewayRequest represents the request to update foreign gateway route.
type UpdateForeignGatewayRequest struct {
	Gateway string `json:"gateway"`
}

// ForeignGatewayResponse represents the response for foreign gateway operations.
type ForeignGatewayResponse struct {
	Gateway       string `json:"gateway"`
	RoutesUpdated int    `json:"routesUpdated,omitempty"`
}

// AddForeignSiteRequest adds a site that always uses the foreign link.
type AddForeignSiteRequest struct {
	// Address is a domain, IPv4 address or IPv4 range; a pasted URL is reduced to its host.
	Address string `json:"address" example:"chatgpt.com"`
}

// ForeignSiteResponse is one site that always uses the foreign link.
type ForeignSiteResponse struct {
	ID      string `json:"id" example:"*1A"`
	Address string `json:"address" example:"chatgpt.com"`
	// Route is how the site leaves: "starlink" directly, or "vpn" for a
	// site whose server is in Iran, so it never sees the Starlink IP.
	Route string `json:"route" example:"starlink"`
	// IranianIPs lists the site's addresses on the Iranian IP list; the
	// firewall keeps those off Starlink.
	IranianIPs []string `json:"iranianIps,omitempty" example:"130.193.77.35"`
}

// IranSiteVPNResponse is a VPN client hand-added Iranian sites may use.
type IranSiteVPNResponse struct {
	Name    string `json:"name" example:"edmund-arden-l2tp-client"`
	Label   string `json:"label" example:"T"`
	Type    string `json:"type" example:"l2tp-out"`
	Running bool   `json:"running"`
	// Order is the client's place among the ticked ones (1 is tried first), or 0 when not ticked.
	Order int `json:"order"`
	// InUse is true for the ticked client currently carrying the sites.
	InUse bool `json:"inUse"`
}

// SetIranSiteVPNsRequest lists the VPN clients Iranian sites may use, in order.
type SetIranSiteVPNsRequest struct {
	Clients []string `json:"clients" example:"edmund-arden-l2tp-client"`
}
