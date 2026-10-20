package handler

// AddV2RayClientRequest represents a request to add a V2Ray client from a
// share link. When Comment is empty, the label carried in the link is used.
type AddV2RayClientRequest struct {
	Link     string `json:"link" example:"vless://uuid@example.com:443?security=reality&sni=www.example.com&pbk=...#Germany"`
	Comment  string `json:"comment,omitempty" example:"Germany"`
	Disabled *bool  `json:"disabled" example:"false"`
}

// V2RayClientTaskStatus reports the progress of a V2Ray client creation.
type V2RayClientTaskStatus struct {
	Name    string `json:"name" example:"v2ray-brave-otter"`
	Phase   string `json:"phase" example:"pulling"`
	Message string `json:"message" example:"downloading ghcr.io/sagernet/sing-box:v1.14.3"`
	Done    bool   `json:"done"`
	Failed  bool   `json:"failed"`
}

// V2RayClientDetailsResponse describes a V2Ray client. The share link's
// secrets stay on the router and are never returned.
type V2RayClientDetailsResponse struct {
	Name     string `json:"name" example:"v2ray-brave-otter"`
	Comment  string `json:"comment,omitempty" example:"Germany"`
	Protocol string `json:"protocol" example:"vless"`
	Server   string `json:"server" example:"example.com:443"`
	Address  string `json:"address,omitempty" example:"192.168.50.10"`
	Running  bool   `json:"running"`
	Disabled bool   `json:"disabled"`
	Pulling  bool   `json:"pulling"`
}
