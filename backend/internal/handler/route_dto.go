package handler

// UpdateForeignGatewayRequest represents the request to update foreign gateway route.
type UpdateForeignGatewayRequest struct {
	Gateway string `json:"gateway"`
}

// ForeignGatewayResponse represents the response for foreign gateway operations.
type ForeignGatewayResponse struct {
	Gateway       string `json:"gateway"`
	RoutesUpdated int    `json:"routesUpdated,omitempty"`
}

// SetVPNBypassRequest turns the emergency VPN bypass on or off.
type SetVPNBypassRequest struct {
	Enabled *bool `json:"enabled" example:"true"`
}

// VPNBypassResponse describes the emergency VPN bypass.
type VPNBypassResponse struct {
	// Enabled is true while VPN traffic goes straight out the foreign link.
	Enabled bool `json:"enabled"`
	// RestoreTo names the VPN client turning the bypass off returns to.
	RestoreTo string `json:"restoreTo,omitempty" example:"elder-josephine-l2tp-client"`
}
