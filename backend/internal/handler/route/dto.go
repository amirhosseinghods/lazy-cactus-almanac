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
