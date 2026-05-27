package api

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"kosiro/agent/internal/awg"
	"kosiro/agent/internal/db"
	"kosiro/agent/internal/dockerctrl"
	"kosiro/agent/internal/metrics"
	"kosiro/agent/internal/models"
	"kosiro/agent/internal/mtproto"
	"kosiro/agent/internal/singbox"
	"kosiro/agent/internal/subscription"
	"kosiro/agent/internal/xray"
)

const (
	settingSubscription = "kosiro.subscription"
	settingXray         = "kosiro.xray"
	settingSingbox      = "kosiro.singbox"
	settingPublicHost   = "kosiro.public_host"
)

type Handler struct {
	store      *db.Store
	jwtSecret  string
	adminToken string
	dataDir    string
	composeDir string
	collector  *metrics.Collector
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "kosiro-agent"})
}

func (h *Handler) IssueToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AdminToken    string `json:"admin_token"`
		InstallSecret string `json:"install_secret"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	install := os.Getenv("KOSIRO_INSTALL_SECRET")
	if install != "" && body.InstallSecret == install {
		// ok
	} else if h.adminToken != "" && len(body.AdminToken) == len(h.adminToken) {
		if subtle.ConstantTimeCompare([]byte(body.AdminToken), []byte(h.adminToken)) != 1 {
			writeErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
	} else {
		writeErr(w, http.StatusUnauthorized, "install_secret or admin_token required")
		return
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "admin",
		"exp": time.Now().Add(8760 * time.Hour).Unix(),
	})
	signed, err := tok.SignedString([]byte(h.jwtSecret))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": signed, "token_type": "Bearer"})
}

func (h *Handler) RotateToken(w http.ResponseWriter, r *http.Request) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "admin",
		"exp": time.Now().Add(8760 * time.Hour).Unix(),
	})
	signed, err := tok.SignedString([]byte(h.jwtSecret))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": signed})
}

func (h *Handler) SystemMetrics(w http.ResponseWriter, r *http.Request) {
	m, err := h.collector.Snapshot()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (h *Handler) MetricsHistory(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	now := time.Now().Unix()
	var from int64
	switch rng {
	case "month":
		from = now - 31*86400
	default:
		from = now - 86400
	}
	pts, err := h.store.MetricsHistory(from)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"range": rng, "points": pts})
}

func (h *Handler) StaleProtocols(w http.ResponseWriter, r *http.Request) {
	hints, err := h.store.StaleProtocolStats(14, 60)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hints": hints})
}

func (h *Handler) ListProtocols(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListProtocols()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"protocols": list})
}

func (h *Handler) GetProtocol(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, err := h.store.GetProtocol(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *Handler) PutProtocol(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cur, err := h.store.GetProtocol(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var body models.Protocol
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	body.ID = cur.ID
	body.Type = cur.Type
	if body.Config == nil {
		body.Config = cur.Config
	}
	if err := h.store.UpdateProtocol(body); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.regenerateXray()
	_ = h.regenerateSidecars()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) InstallProtocol(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, err := h.store.GetProtocol(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if p.Type == models.ProtoMTProto {
		if cfgStr(p.Config, "secret", "") == "" {
			p.Config["secret"] = strings.ReplaceAll(uuid.NewString(), "-", "")
		}
	}
	p.Installed = true
	if err := h.store.UpdateProtocol(p); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	users, _ := h.store.ListUsers()
	switch p.Type {
	case models.ProtoHysteria2:
		_ = singbox.WriteHysteria2(h.dataDir, p, users)
	case models.ProtoMTProto:
		port := cfgInt(p.Config, "port", 8446)
		sec := cfgStr(p.Config, "secret", "")
		_ = mtproto.WriteEnvFile(h.dataDir, port, sec, cfgStr(p.Config, "sponsor_channel", ""), cfgBool(p.Config, "public_proxy", false))
	case models.ProtoAmneziaWG:
		_ = awg.WriteServerHint(h.dataDir, cfgInt(p.Config, "port", 51820), cfgStr(p.Config, "preset", "balanced"))
	}
	_ = h.regenerateXray()
	_ = h.regenerateSidecars()
	_ = h.syncSidecarContainers()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "installed": true})
}

func (h *Handler) ApplyProtocols(w http.ResponseWriter, r *http.Request) {
	if err := h.regenerateXray(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.regenerateSidecars()
	_ = h.syncSidecarContainers()
	_ = dockerctrl.RestartXray(h.composeDir)
	if cname := os.Getenv("KOSIRO_XRAY_CONTAINER"); cname != "" {
		_ = exec.Command("docker", "restart", cname).Run()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) regenerateSidecars() error {
	protos, err := h.store.ListProtocols()
	if err != nil {
		return err
	}
	users, err := h.store.ListUsers()
	if err != nil {
		return err
	}
	for _, pr := range protos {
		if !pr.Installed {
			continue
		}
		if pr.Type == models.ProtoHysteria2 {
			_ = singbox.WriteHysteria2(h.dataDir, pr, users)
		}
	}
	return nil
}

func (h *Handler) syncSidecarContainers() error {
	protos, err := h.store.ListProtocols()
	if err != nil {
		return err
	}
	return dockerctrl.SyncSidecars(h.composeDir, h.dataDir, protos)
}

func (h *Handler) regenerateXray() error {
	protos, err := h.store.ListProtocols()
	if err != nil {
		return err
	}
	users, err := h.store.ListUsers()
	if err != nil {
		return err
	}
	host := h.publicHost()
	xs := h.loadXraySettings()
	cfg, err := xray.BuildConfig(host, protos, users, xs.APIListen, xs.LogLevel)
	if err != nil {
		return err
	}
	return xray.WriteConfigFile(h.dataDir, cfg)
}

func (h *Handler) publicHost() string {
	v, _ := h.store.GetSetting(settingPublicHost)
	if v != "" {
		return v
	}
	if h := os.Getenv("KOSIRO_PUBLIC_HOST"); h != "" {
		return h
	}
	return "127.0.0.1"
}

func cfgInt(m map[string]interface{}, k string, def int) int {
	if m == nil {
		return def
	}
	v, ok := m[k]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return def
	}
}

func cfgStr(m map[string]interface{}, k, def string) string {
	if m == nil {
		return def
	}
	v, ok := m[k]
	if !ok {
		return def
	}
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

func cfgBool(m map[string]interface{}, k string, def bool) bool {
	if m == nil {
		return def
	}
	v, ok := m[k]
	if !ok {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

func (h *Handler) loadXraySettings() models.XraySettings {
	var xs models.XraySettings
	xs.LogLevel = "warning"
	xs.APIListen = "0.0.0.0:10085"
	raw, _ := h.store.GetSetting(settingXray)
	if raw == "" {
		return xs
	}
	_ = json.Unmarshal([]byte(raw), &xs)
	return xs
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": list})
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var body models.VPNUser
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if body.Name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	body.ID = uuid.NewString()
	body.UUID = uuid.NewString()
	body.SubscriptionToken = uuid.NewString()
	if body.Email == "" {
		body.Email = body.UUID + "@kosiro.local"
	}
	if body.BillingPeriod == "" {
		body.BillingPeriod = models.BillingMonth
	}
	if body.ExhaustPolicy == "" {
		body.ExhaustPolicy = models.ExhaustDisconnect
	}
	body.PeriodStartUnix = time.Now().Unix()
	body.CreatedAt = time.Now().UTC()
	if err := h.store.InsertUser(body); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.regenerateXray()
	_ = h.regenerateSidecars()
	writeJSON(w, http.StatusCreated, body)
}

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	u, err := h.store.GetUser(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *Handler) PatchUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cur, err := h.store.GetUser(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var patch map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if v, ok := patch["name"]; ok {
		_ = json.Unmarshal(v, &cur.Name)
	}
	if v, ok := patch["email"]; ok {
		_ = json.Unmarshal(v, &cur.Email)
	}
	if v, ok := patch["speed_limit_kbps"]; ok {
		var p *int
		_ = json.Unmarshal(v, &p)
		cur.SpeedLimitKbps = p
	}
	if v, ok := patch["billing_period"]; ok {
		_ = json.Unmarshal(v, &cur.BillingPeriod)
	}
	if v, ok := patch["traffic_limit_bytes"]; ok {
		_ = json.Unmarshal(v, &cur.TrafficLimitBytes)
	}
	if v, ok := patch["rollover_unused"]; ok {
		_ = json.Unmarshal(v, &cur.RolloverUnused)
	}
	if v, ok := patch["exhaust_policy"]; ok {
		_ = json.Unmarshal(v, &cur.ExhaustPolicy)
	}
	if v, ok := patch["throttle_value"]; ok {
		_ = json.Unmarshal(v, &cur.ThrottleValue)
	}
	if v, ok := patch["throttle_unit"]; ok {
		var tu *models.ThrottleUnit
		_ = json.Unmarshal(v, &tu)
		cur.ThrottleUnit = tu
	}
	if v, ok := patch["enabled_protocol_ids"]; ok {
		_ = json.Unmarshal(v, &cur.EnabledProtocolIDs)
	}
	if v, ok := patch["traffic_used_bytes"]; ok {
		_ = json.Unmarshal(v, &cur.TrafficUsedBytes)
	}
	if err := h.store.UpdateUser(cur); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.regenerateXray()
	_ = h.regenerateSidecars()
	writeJSON(w, http.StatusOK, cur)
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.store.DeleteUser(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.regenerateXray()
	_ = h.regenerateSidecars()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) UserSubscription(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	u, err := h.store.GetUser(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	protos, _ := h.store.ListProtocols()
	host := h.publicHost()
	uris := subscription.CollectURIsForUser(host, protos, u)
	sub := h.loadSubscriptionSettings()
	base := sub.BasePublicURL
	if base == "" {
		base = "https://" + host
	}
	path := sub.SubscriptionPath
	if path == "" {
		path = "/sub/"
	}
	subURL := base + path + u.SubscriptionToken
	writeJSON(w, http.StatusOK, map[string]any{
		"subscription_url": subURL,
		"uris":             uris,
		"notes": map[string]string{
			"awg":     "AmneziaWG: используйте экспорт .conf или клиент Amnezia VPN.",
			"mtproto": "Импорт через Telegram или ссылку tg://proxy",
		},
	})
}

func (h *Handler) UserTrafficHistory(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetUser(id); err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	rng := r.URL.Query().Get("range")
	protoFilter := r.URL.Query().Get("protocol")
	now := time.Now().Unix()
	var from int64
	switch rng {
	case "month":
		from = now - 31*86400
	default:
		from = now - 86400
	}
	rows, err := h.store.UserTrafficSnapshots(id, from)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type point struct {
		Timestamp int64  `json:"timestamp"`
		Protocol  string `json:"protocol"`
		Bytes     int64  `json:"bytes"`
	}
	var pts []point
	for _, row := range rows {
		if protoFilter != "" && protoFilter != "all" && row.Protocol != protoFilter {
			continue
		}
		pts = append(pts, point{Timestamp: row.Timestamp, Protocol: row.Protocol, Bytes: row.DownBytes + row.UpBytes})
	}
	writeJSON(w, http.StatusOK, map[string]any{"range": rng, "points": pts})
}

func (h *Handler) PublicSubscription(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	u, err := h.store.GetUserBySubToken(token)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	protos, _ := h.store.ListProtocols()
	host := h.publicHost()
	uris := subscription.CollectURIsForUser(host, protos, u)
	enc := subscription.EncodeSubscriptionBase64(uris)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Profile-Update-Interval", "86400")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, enc)
}

func (h *Handler) GetSubscriptionSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.loadSubscriptionSettings())
}

func (h *Handler) loadSubscriptionSettings() models.SubscriptionSettings {
	var s models.SubscriptionSettings
	s.SubscriptionPath = "/sub/"
	s.SubscriptionKind = "v2ray_base64"
	raw, _ := h.store.GetSetting(settingSubscription)
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	return s
}

func (h *Handler) PutSubscriptionSettings(w http.ResponseWriter, r *http.Request) {
	var s models.SubscriptionSettings
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	b, _ := json.Marshal(s)
	if err := h.store.SetSetting(settingSubscription, string(b)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.BasePublicURL != "" {
		if u, err := url.Parse(s.BasePublicURL); err == nil && u.Host != "" {
			_ = h.store.SetSetting(settingPublicHost, u.Hostname())
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) GetXraySettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.loadXraySettings())
}

func (h *Handler) PutXraySettings(w http.ResponseWriter, r *http.Request) {
	var xs models.XraySettings
	if err := json.NewDecoder(r.Body).Decode(&xs); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	b, _ := json.Marshal(xs)
	if err := h.store.SetSetting(settingXray, string(b)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) GetSingboxSettings(w http.ResponseWriter, r *http.Request) {
	var s models.SingboxSettings
	s.LogLevel = "info"
	raw, _ := h.store.GetSetting(settingSingbox)
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handler) PutSingboxSettings(w http.ResponseWriter, r *http.Request) {
	var s models.SingboxSettings
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	b, _ := json.Marshal(s)
	if err := h.store.SetSetting(settingSingbox, string(b)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
