package models

import "time"

type BillingPeriod string

const (
	BillingWeek    BillingPeriod = "week"
	BillingMonth   BillingPeriod = "month"
	BillingHalfYear BillingPeriod = "half_year"
	BillingYear    BillingPeriod = "year"
)

type ExhaustPolicy string

const (
	ExhaustDisconnect ExhaustPolicy = "disconnect"
	ExhaustThrottle   ExhaustPolicy = "throttle"
)

type ThrottleUnit string

const (
	ThrottleKBps ThrottleUnit = "KBps"
	ThrottleMBps ThrottleUnit = "MBps"
	ThrottleGBps ThrottleUnit = "GBps"
)

type ProtocolType string

const (
	ProtoVLESS                 ProtocolType = "vless"
	ProtoVLESSReality          ProtocolType = "vless_reality" // legacy
	ProtoVLESSXHTTP            ProtocolType = "vless_xhttp"   // legacy, hidden
	ProtoVLESSRealityXHTTP     ProtocolType = "vless_reality_xhttp"
	ProtoVLESSRealityTLSMux    ProtocolType = "vless_reality_tls_mux"
	ProtoVMess                 ProtocolType = "vmess"
	ProtoShadowsocks           ProtocolType = "shadowsocks"
	ProtoTrojan                ProtocolType = "trojan"
	ProtoHysteria2             ProtocolType = "hysteria2"
	ProtoTUIC                  ProtocolType = "tuic"
	ProtoAnyTLS                ProtocolType = "anytls"
	ProtoMTProto               ProtocolType = "mtproto"
	ProtoAmneziaWG             ProtocolType = "amneziawg"
)

type SystemMetrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	RAMPercent    float64 `json:"ram_percent"`
	RAMUsedBytes  uint64  `json:"ram_used_bytes"`
	RAMTotalBytes uint64  `json:"ram_total_bytes"`
	NetUpBps      float64 `json:"net_up_bps"`
	NetDownBps    float64 `json:"net_down_bps"`
	DiskPercent   float64 `json:"disk_percent"`
	DiskUsedBytes uint64  `json:"disk_used_bytes"`
	DiskTotalBytes uint64 `json:"disk_total_bytes"`
	Timestamp     int64   `json:"timestamp"`
}

type MetricsHistoryPoint struct {
	Timestamp     int64   `json:"timestamp"`
	CPUPercent    float64 `json:"cpu_percent"`
	RAMPercent    float64 `json:"ram_percent"`
	NetUpBps      float64 `json:"net_up_bps"`
	NetDownBps    float64 `json:"net_down_bps"`
	DiskPercent   float64 `json:"disk_percent"`
}

type Protocol struct {
	ID          string                 `json:"id"`
	Type        ProtocolType           `json:"type"`
	Enabled     bool                   `json:"enabled"`
	Installed   bool                   `json:"installed"`
	DisplayName string                 `json:"display_name"`
	Config      map[string]interface{} `json:"config"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type StaleProtocolHint struct {
	ProtocolType ProtocolType `json:"protocol_type"`
	Message      string       `json:"message"`
	IdleUserPct  float64      `json:"idle_user_percent"`
}

type VPNUser struct {
	ID                 string          `json:"id"`
	Name               string          `json:"name"`
	Email              string          `json:"email"`
	UUID               string          `json:"uuid"`
	SubscriptionToken  string          `json:"subscription_token"`
	SpeedLimitKbps     *int            `json:"speed_limit_kbps,omitempty"`
	BillingPeriod      BillingPeriod   `json:"billing_period"`
	TrafficLimitBytes  int64           `json:"traffic_limit_bytes"`
	RolloverUnused     bool            `json:"rollover_unused"`
	ExhaustPolicy      ExhaustPolicy   `json:"exhaust_policy"`
	ThrottleValue      *float64        `json:"throttle_value,omitempty"`
	ThrottleUnit       *ThrottleUnit   `json:"throttle_unit,omitempty"`
	EnabledProtocolIDs []string        `json:"enabled_protocol_ids"`
	TrafficUsedBytes   int64           `json:"traffic_used_bytes"`
	PeriodStartUnix    int64           `json:"period_start_unix"`
	Online             bool            `json:"online"`
	LastSeenUnix       int64           `json:"last_seen_unix"`
	CreatedAt          time.Time       `json:"created_at"`
}

type TrafficByProtocol struct {
	Protocol string `json:"protocol"`
	UpBytes  int64  `json:"up_bytes"`
	DownBytes int64 `json:"down_bytes"`
}

type UserTrafficHistoryPoint struct {
	Timestamp int64               `json:"timestamp"`
	ByProto   []TrafficByProtocol `json:"by_protocol"`
	TotalBytes int64              `json:"total_bytes"`
}

type SubscriptionSettings struct {
	BasePublicURL     string `json:"base_public_url"`
	SubscriptionPath  string `json:"subscription_path"`
	TLSCertPath       string `json:"tls_cert_path,omitempty"`
	TLSKeyPath        string `json:"tls_key_path,omitempty"`
	UseLetsEncrypt    bool   `json:"use_lets_encrypt"`
	LetsEncryptDomain string `json:"lets_encrypt_domain,omitempty"`
	SubscriptionKind  string `json:"subscription_kind"` // v2ray_base64, clash
}

type XraySettings struct {
	LogLevel           string                 `json:"log_level"`
	APIListen          string                 `json:"api_listen"`
	PolicyJSON         map[string]interface{} `json:"policy_patch,omitempty"`
	RoutingJSON        map[string]interface{} `json:"routing_patch,omitempty"`
}

type SingboxSettings struct {
	LogLevel string `json:"log_level"`
}
