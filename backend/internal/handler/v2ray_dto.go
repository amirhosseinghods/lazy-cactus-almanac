package handler

import "time"

// AddV2RayClientRequest represents a request to add a V2Ray client from either
// a single share link or a subscription URL (exactly one of the two). With a
// subscription, sing-box keeps traffic on whichever server answers fastest.
// When Comment is empty for a share link, the label carried in the link is used.
type AddV2RayClientRequest struct {
	Link         string `json:"link,omitempty" example:"vless://uuid@example.com:443?security=reality&sni=www.example.com&pbk=...#Germany"`
	Subscription string `json:"subscription,omitempty" example:"https://sub.example.com/api/v1/client/subscribe?token=..."`
	Comment      string `json:"comment,omitempty" example:"Germany"`
	Disabled     *bool  `json:"disabled" example:"false"`
}

// V2RayClientTaskStatus reports the progress of a V2Ray client creation.
type V2RayClientTaskStatus struct {
	Name    string `json:"name" example:"v2ray-brave-otter"`
	Phase   string `json:"phase" example:"pulling"`
	Message string `json:"message" example:"downloading ghcr.io/amirhosseinghods/sing-box-slim:1.14.3"`
	Done    bool   `json:"done"`
	Failed  bool   `json:"failed"`
	// Image download progress in bytes; zero outside the downloading phase.
	BytesDone  int64 `json:"bytesDone,omitempty"`
	BytesTotal int64 `json:"bytesTotal,omitempty"`
}

// V2RayClientDetailsResponse describes a V2Ray client. The share link's
// secrets stay on the router and are never returned.
type V2RayClientDetailsResponse struct {
	Name     string `json:"name" example:"v2ray-brave-otter"`
	Comment  string `json:"comment,omitempty" example:"Germany"`
	Mode     string `json:"mode" example:"subscription" enums:"link,subscription"`
	Protocol string `json:"protocol" example:"vless"`
	Server   string `json:"server" example:"example.com:443"`
	Address  string `json:"address,omitempty" example:"192.168.50.10"`
	Running  bool   `json:"running"`
	Disabled bool   `json:"disabled"`
	Pulling  bool   `json:"pulling"`
	// Servers lists the servers behind this client; Selected marks the one
	// in use when the router can tell.
	Servers     []V2RayServer `json:"servers,omitempty"`
	Skipped     int           `json:"skipped,omitempty"`
	RefreshedAt *time.Time    `json:"refreshedAt,omitempty"`
}

// V2RayServer is one server of a V2Ray client.
type V2RayServer struct {
	Name     string `json:"name,omitempty" example:"Germany 1"`
	Protocol string `json:"protocol" example:"vless"`
	Server   string `json:"server" example:"de1.example.com:443"`
	Selected bool   `json:"selected"`
}

// V2RayRefreshResponse reports the outcome of a subscription refresh.
type V2RayRefreshResponse struct {
	Changed     bool      `json:"changed"`
	ServerCount int       `json:"serverCount"`
	Skipped     int       `json:"skipped,omitempty"`
	RefreshedAt time.Time `json:"refreshedAt"`
}
