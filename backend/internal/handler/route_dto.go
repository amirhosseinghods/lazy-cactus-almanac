package handler

import "time"

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

// IranIPListResponse describes the Iranian IP list used for split routing.
type IranIPListResponse struct {
	// Entries is how many addresses DOMAddList holds.
	Entries int `json:"entries" example:"1961"`
	// ManagedByPanel is true once the panel has updated the list itself.
	ManagedByPanel bool       `json:"managedByPanel"`
	UpdatedAt      *time.Time `json:"updatedAt,omitempty"`
	Sources        []string   `json:"sources"`
}

// IranIPUpdateResponse reports the outcome of an Iranian IP list update.
type IranIPUpdateResponse struct {
	Total     int       `json:"total" example:"1961"`
	Added     int       `json:"added" example:"40"`
	Removed   int       `json:"removed" example:"12"`
	UpdatedAt time.Time `json:"updatedAt"`
}
