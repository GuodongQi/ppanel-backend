package dto

// RealityScanConfig is the administrator's schedule, probe list and
// switch policy for Reality camouflage targets.
type RealityScanConfig struct {
	Enabled             bool     `json:"enabled"`
	DailyTime           string   `json:"daily_time"`
	Port                int      `json:"port"`
	Radius              int      `json:"radius"`
	ScanServerNeighbors bool     `json:"scan_server_neighbors"`
	Seeds               []string `json:"seeds"`
	Candidates          []string `json:"candidates"`
	AutoSwitch          bool     `json:"auto_switch"`
	ScoreMargin         int      `json:"score_margin"`
	CooldownHours       int      `json:"cooldown_hours"`
	ServerIDs           []int64  `json:"server_ids"`
	Threads             int      `json:"threads"`
	TimeoutSeconds      int      `json:"timeout_seconds"`
	MaxCertBytes        int      `json:"max_cert_bytes"`
}

// RealityScanResult is one probed target after scoring.
type RealityScanResult struct {
	IP         string `json:"ip"`
	Origin     string `json:"origin"`
	DialHost   string `json:"dial_host"`
	Source     string `json:"source"`
	Port       int    `json:"port"`
	TLS        string `json:"tls,omitempty"`
	ALPN       string `json:"alpn,omitempty"`
	Curve      string `json:"curve,omitempty"`
	CertDomain string `json:"cert_domain,omitempty"`
	CertIssuer string `json:"cert_issuer,omitempty"`
	CertBytes  int    `json:"cert_bytes,omitempty"`
	LatencyMS  int    `json:"latency_ms,omitempty"`
	Feasible   bool   `json:"feasible"`
	Score      int    `json:"score"`
	Error      string `json:"error,omitempty"`
}

// RealityScanSwitch records what happened to one Reality protocol.
type RealityScanSwitch struct {
	ServerID   int64  `json:"server_id"`
	ServerName string `json:"server_name"`
	Protocol   string `json:"protocol"`
	FromSNI    string `json:"from_sni"`
	FromAddr   string `json:"from_addr"`
	ToSNI      string `json:"to_sni,omitempty"`
	ToAddr     string `json:"to_addr,omitempty"`
	ToPort     int    `json:"to_port,omitempty"`
	Score      int    `json:"score,omitempty"`
	Reason     string `json:"reason"`
}

// RealityScanReport is the latest scan, kept for the admin page.
type RealityScanReport struct {
	Running       bool                `json:"running"`
	StartedAt     string              `json:"started_at,omitempty"`
	FinishedAt    string              `json:"finished_at,omitempty"`
	LastCompleted string              `json:"last_completed,omitempty"`
	LastAttempt   string              `json:"last_attempt,omitempty"`
	Error         string              `json:"error,omitempty"`
	Scanned       int                 `json:"scanned"`
	Feasible      int                 `json:"feasible"`
	Truncated     bool                `json:"truncated"`
	Applied       bool                `json:"applied"`
	Results       []RealityScanResult `json:"results"`
	Switches      []RealityScanSwitch `json:"switches"`
}

// RealityScanView is the config and the latest report together.
type RealityScanView struct {
	Config RealityScanConfig `json:"config"`
	Report RealityScanReport `json:"report"`
}
