package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"kosiro/agent/internal/models"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	d, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	if err := d.Ping(); err != nil {
		return nil, err
	}
	return &Store{db: d}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS protocols (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 0,
			installed INTEGER NOT NULL DEFAULT 0,
			display_name TEXT,
			config_json TEXT,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS vpn_users (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			email TEXT,
			uuid TEXT NOT NULL,
			subscription_token TEXT NOT NULL UNIQUE,
			speed_limit_kbps INTEGER,
			billing_period TEXT NOT NULL,
			traffic_limit_bytes INTEGER NOT NULL,
			rollover_unused INTEGER NOT NULL DEFAULT 0,
			exhaust_policy TEXT NOT NULL,
			throttle_value REAL,
			throttle_unit TEXT,
			enabled_protocol_ids TEXT NOT NULL,
			traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
			period_start_unix INTEGER NOT NULL,
			last_seen_unix INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS metrics_history (
			ts INTEGER PRIMARY KEY,
			cpu REAL NOT NULL,
			ram REAL NOT NULL,
			net_up REAL NOT NULL,
			net_down REAL NOT NULL,
			disk REAL NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS user_traffic_snapshots (
			ts INTEGER NOT NULL,
			user_id TEXT NOT NULL,
			protocol TEXT NOT NULL,
			up_bytes INTEGER NOT NULL DEFAULT 0,
			down_bytes INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (ts, user_id, protocol)
		)`,
		`CREATE TABLE IF NOT EXISTS protocol_usage (
			user_id TEXT NOT NULL,
			protocol TEXT NOT NULL,
			last_bytes_ts INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, protocol)
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	if err := s.seedDefaultProtocols(); err != nil {
		return err
	}
	return s.migrateProtocolLayout()
}

var hiddenProtocolIDs = map[string]struct{}{
	"proto_vless_xhttp":         {},
	"proto_vless_reality_xhttp": {},
	"proto_vless_reality_mux":   {},
	"proto_ss":                  {},
}

func (s *Store) IsProtocolVisible(id string) bool {
	_, hidden := hiddenProtocolIDs[id]
	return !hidden
}

func (s *Store) migrateProtocolLayout() error {
	for id := range hiddenProtocolIDs {
		_, _ = s.db.Exec(`UPDATE protocols SET enabled=0 WHERE id=?`, id)
	}
	var typ, cfgRaw string
	err := s.db.QueryRow(`SELECT type, config_json FROM protocols WHERE id='proto_vless'`).Scan(&typ, &cfgRaw)
	if err != nil {
		return nil
	}
	var cfg map[string]interface{}
	_ = json.Unmarshal([]byte(cfgRaw), &cfg)
	if cfg == nil {
		cfg = map[string]interface{}{}
	}
	changed := false
	if typ != string(models.ProtoVLESS) {
		typ = string(models.ProtoVLESS)
		changed = true
	}
	if _, ok := cfg["transport"]; !ok {
		cfg["transport"] = "tcp"
		cfg["security"] = "reality"
		changed = true
	}
	if _, ok := cfg["remark"]; !ok {
		cfg["remark"] = "Kosiro-VLESS"
		changed = true
	}
	if changed {
		b, _ := json.Marshal(cfg)
		_, _ = s.db.Exec(`UPDATE protocols SET type=?, display_name=?, config_json=? WHERE id='proto_vless'`, typ, "VLESS", string(b))
	}
	return nil
}

func (s *Store) seedDefaultProtocols() error {
	now := time.Now().UTC().Format(time.RFC3339)
	defaults := []struct {
		id, typ, name string
		cfg           map[string]interface{}
	}{
		{"proto_vless", string(models.ProtoVLESS), "VLESS", map[string]interface{}{
			"port": 443, "remark": "Kosiro-VLESS", "transport": "tcp", "security": "reality",
			"sni": "www.cloudflare.com", "dest": "www.cloudflare.com:443", "flow": "xtls-rprx-vision",
			"fingerprint": "chrome", "mux": false, "xhttp_path": "/", "xhttp_mode": "auto",
		}},
		{"proto_trojan", string(models.ProtoTrojan), "Trojan", map[string]interface{}{
			"port": 8444, "remark": "Kosiro-Trojan", "network": "tcp", "security": "tls", "sni": "",
		}},
		{"proto_vmess", string(models.ProtoVMess), "VMess", map[string]interface{}{
			"port": 10086, "remark": "Kosiro-VMess", "network": "tcp", "security": "none",
		}},
		{"proto_hy2", string(models.ProtoHysteria2), "Hysteria2", map[string]interface{}{"port": 8445, "remark": "Kosiro-Hy2", "sni": ""}},
		{"proto_tuic", string(models.ProtoTUIC), "TUIC", map[string]interface{}{"port": 8447, "remark": "Kosiro-TUIC", "sni": "", "congestion_control": "bbr"}},
		{"proto_anytls", string(models.ProtoAnyTLS), "AnyTLS", map[string]interface{}{"port": 8448, "remark": "Kosiro-AnyTLS", "sni": ""}},
		{"proto_mtproto", string(models.ProtoMTProto), "MTProto", map[string]interface{}{"port": 8446, "secret": "", "sponsor_channel": "", "public_proxy": false}},
		{"proto_awg", string(models.ProtoAmneziaWG), "AmneziaWG 2", map[string]interface{}{"port": 51820, "preset": "balanced"}},
	}
	for _, d := range defaults {
		var cnt int
		_ = s.db.QueryRow(`SELECT COUNT(1) FROM protocols WHERE id=?`, d.id).Scan(&cnt)
		if cnt > 0 {
			continue
		}
		b, _ := json.Marshal(d.cfg)
		_, err := s.db.Exec(`INSERT INTO protocols(id,type,enabled,installed,display_name,config_json,updated_at) VALUES(?,?,0,0,?,?,?)`,
			d.id, d.typ, d.name, string(b), now)
		if err != nil {
			return err
		}
	}
	return nil
}

const SettingAdminKey = "kosiro.admin_key"

func (s *Store) EnsureAdminKey(key string) error {
	if key == "" {
		return nil
	}
	return s.SetSetting(SettingAdminKey, key)
}

func (s *Store) AdminKey() (string, error) {
	return s.GetSetting(SettingAdminKey)
}

func (s *Store) EnsureJWTSecret() (string, error) {
	const key = "jwt_secret"
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == nil && v != "" {
		return v, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	sec, err := randomHex(32)
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, sec)
	return sec, err
}

func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSetting(key, val string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, val)
	return err
}

func (s *Store) InsertMetrics(ts int64, cpu, ram, netUp, netDown, disk float64) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO metrics_history(ts,cpu,ram,net_up,net_down,disk) VALUES(?,?,?,?,?,?)`,
		ts, cpu, ram, netUp, netDown, disk)
	return err
}

func (s *Store) MetricsHistory(fromTs int64) ([]models.MetricsHistoryPoint, error) {
	rows, err := s.db.Query(`SELECT ts, cpu, ram, net_up, net_down, disk FROM metrics_history WHERE ts >= ? ORDER BY ts ASC`, fromTs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.MetricsHistoryPoint
	for rows.Next() {
		var p models.MetricsHistoryPoint
		if err := rows.Scan(&p.Timestamp, &p.CPUPercent, &p.RAMPercent, &p.NetUpBps, &p.NetDownBps, &p.DiskPercent); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) ListProtocols() ([]models.Protocol, error) {
	rows, err := s.db.Query(`SELECT id,type,enabled,installed,display_name,config_json,updated_at FROM protocols ORDER BY type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []models.Protocol
	for rows.Next() {
		var p models.Protocol
		var cfgJSON string
		var en, ins int
		var updated string
		if err := rows.Scan(&p.ID, &p.Type, &en, &ins, &p.DisplayName, &cfgJSON, &updated); err != nil {
			return nil, err
		}
		p.Enabled = en != 0
		p.Installed = ins != 0
		p.Config = map[string]interface{}{}
		_ = json.Unmarshal([]byte(cfgJSON), &p.Config)
		p.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		if !s.IsProtocolVisible(p.ID) {
			continue
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

func (s *Store) GetProtocol(id string) (models.Protocol, error) {
	var p models.Protocol
	var cfgJSON string
	var en, ins int
	var updated string
	err := s.db.QueryRow(`SELECT id,type,enabled,installed,display_name,config_json,updated_at FROM protocols WHERE id=?`, id).
		Scan(&p.ID, &p.Type, &en, &ins, &p.DisplayName, &cfgJSON, &updated)
	if err != nil {
		return p, err
	}
	p.Enabled = en != 0
	p.Installed = ins != 0
	_ = json.Unmarshal([]byte(cfgJSON), &p.Config)
	p.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	return p, nil
}

func (s *Store) UpdateProtocol(p models.Protocol) error {
	b, err := json.Marshal(p.Config)
	if err != nil {
		return err
	}
	en, ins := 0, 0
	if p.Enabled {
		en = 1
	}
	if p.Installed {
		ins = 1
	}
	_, err = s.db.Exec(`UPDATE protocols SET enabled=?, installed=?, display_name=?, config_json=?, updated_at=? WHERE id=?`,
		en, ins, p.DisplayName, string(b), time.Now().UTC().Format(time.RFC3339), p.ID)
	return err
}

func (s *Store) ListUsers() ([]models.VPNUser, error) {
	rows, err := s.db.Query(`SELECT id,name,email,uuid,subscription_token,speed_limit_kbps,billing_period,traffic_limit_bytes,rollover_unused,exhaust_policy,throttle_value,throttle_unit,enabled_protocol_ids,traffic_used_bytes,period_start_unix,last_seen_unix,created_at FROM vpn_users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []models.VPNUser
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(rows rowScanner) (models.VPNUser, error) {
	var u models.VPNUser
	var speed sql.NullInt64
	var throttleVal sql.NullFloat64
	var throttleUnit sql.NullString
	var protoIDs string
	var created string
	var rolloverInt int
	if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.UUID, &u.SubscriptionToken, &speed, &u.BillingPeriod, &u.TrafficLimitBytes, &rolloverInt, &u.ExhaustPolicy, &throttleVal, &throttleUnit, &protoIDs, &u.TrafficUsedBytes, &u.PeriodStartUnix, &u.LastSeenUnix, &created); err != nil {
		return u, err
	}
	u.RolloverUnused = rolloverInt != 0
	if speed.Valid {
		v := int(speed.Int64)
		u.SpeedLimitKbps = &v
	}
	if throttleVal.Valid {
		v := throttleVal.Float64
		u.ThrottleValue = &v
	}
	if throttleUnit.Valid {
		tu := models.ThrottleUnit(throttleUnit.String)
		u.ThrottleUnit = &tu
	}
	_ = json.Unmarshal([]byte(protoIDs), &u.EnabledProtocolIDs)
	u.CreatedAt, _ = time.Parse(time.RFC3339, created)
	u.Online = time.Now().Unix()-u.LastSeenUnix < 180
	return u, nil
}

func (s *Store) GetUser(id string) (models.VPNUser, error) {
	row := s.db.QueryRow(`SELECT id,name,email,uuid,subscription_token,speed_limit_kbps,billing_period,traffic_limit_bytes,rollover_unused,exhaust_policy,throttle_value,throttle_unit,enabled_protocol_ids,traffic_used_bytes,period_start_unix,last_seen_unix,created_at FROM vpn_users WHERE id=?`, id)
	return scanUser(row)
}

func (s *Store) GetUserBySubToken(tok string) (models.VPNUser, error) {
	row := s.db.QueryRow(`SELECT id,name,email,uuid,subscription_token,speed_limit_kbps,billing_period,traffic_limit_bytes,rollover_unused,exhaust_policy,throttle_value,throttle_unit,enabled_protocol_ids,traffic_used_bytes,period_start_unix,last_seen_unix,created_at FROM vpn_users WHERE subscription_token=?`, tok)
	return scanUser(row)
}

func (s *Store) InsertUser(u models.VPNUser) error {
	protoIDs, _ := json.Marshal(u.EnabledProtocolIDs)
	speed := sqlNullInt(u.SpeedLimitKbps)
	tv, tu := sqlNullFloatString(u.ThrottleValue, u.ThrottleUnit)
	_, err := s.db.Exec(`INSERT INTO vpn_users(id,name,email,uuid,subscription_token,speed_limit_kbps,billing_period,traffic_limit_bytes,rollover_unused,exhaust_policy,throttle_value,throttle_unit,enabled_protocol_ids,traffic_used_bytes,period_start_unix,last_seen_unix,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.Name, u.Email, u.UUID, u.SubscriptionToken, speed, u.BillingPeriod, u.TrafficLimitBytes, boolToInt(u.RolloverUnused), u.ExhaustPolicy, tv, tu, string(protoIDs), u.TrafficUsedBytes, u.PeriodStartUnix, u.LastSeenUnix, u.CreatedAt.UTC().Format(time.RFC3339))
	return err
}

func (s *Store) UpdateUser(u models.VPNUser) error {
	protoIDs, _ := json.Marshal(u.EnabledProtocolIDs)
	speed := sqlNullInt(u.SpeedLimitKbps)
	tv, tu := sqlNullFloatString(u.ThrottleValue, u.ThrottleUnit)
	_, err := s.db.Exec(`UPDATE vpn_users SET name=?,email=?,speed_limit_kbps=?,billing_period=?,traffic_limit_bytes=?,rollover_unused=?,exhaust_policy=?,throttle_value=?,throttle_unit=?,enabled_protocol_ids=?,traffic_used_bytes=?,period_start_unix=?,last_seen_unix=? WHERE id=?`,
		u.Name, u.Email, speed, u.BillingPeriod, u.TrafficLimitBytes, boolToInt(u.RolloverUnused), u.ExhaustPolicy, tv, tu, string(protoIDs), u.TrafficUsedBytes, u.PeriodStartUnix, u.LastSeenUnix, u.ID)
	return err
}

func (s *Store) DeleteUser(id string) error {
	_, err := s.db.Exec(`DELETE FROM vpn_users WHERE id=?`, id)
	return err
}

func (s *Store) RecordProtocolUsage(userID, protocol string, ts int64) error {
	_, err := s.db.Exec(`INSERT INTO protocol_usage(user_id,protocol,last_bytes_ts) VALUES(?,?,?) ON CONFLICT(user_id,protocol) DO UPDATE SET last_bytes_ts=excluded.last_bytes_ts`, userID, protocol, ts)
	return err
}

func (s *Store) StaleProtocolStats(idleDays int, minUserPct float64) ([]models.StaleProtocolHint, error) {
	users, err := s.ListUsers()
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, nil
	}
	cutoff := time.Now().Add(-time.Duration(idleDays) * 24 * time.Hour).Unix()
	protos, err := s.ListProtocols()
	if err != nil {
		return nil, err
	}
	var hints []models.StaleProtocolHint
	for _, pr := range protos {
		if !pr.Installed || !pr.Enabled {
			continue
		}
		idle := 0
		for _, u := range users {
			if !contains(u.EnabledProtocolIDs, pr.ID) {
				continue
			}
			var lastTS int64
			_ = s.db.QueryRow(`SELECT last_bytes_ts FROM protocol_usage WHERE user_id=? AND protocol=?`, u.ID, string(pr.Type)).Scan(&lastTS)
			if lastTS < cutoff || lastTS == 0 {
				idle++
			}
		}
		eligible := countEligible(users, pr.ID)
		if eligible == 0 {
			continue
		}
		pct := float64(idle) / float64(eligible) * 100
		if pct >= minUserPct {
			hints = append(hints, models.StaleProtocolHint{
				ProtocolType: pr.Type,
				Message:      fmt.Sprintf("У %d%% пользователей с этим протоколом не было трафика за %d дн.", int(pct+0.5), idleDays),
				IdleUserPct:  pct,
			})
		}
	}
	return hints, nil
}

func contains(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func countEligible(users []models.VPNUser, protoID string) int {
	n := 0
	for _, u := range users {
		if contains(u.EnabledProtocolIDs, protoID) {
			n++
		}
	}
	return n
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func sqlNullInt(p *int) interface{} {
	if p == nil {
		return nil
	}
	return *p
}

func sqlNullFloatString(v *float64, u *models.ThrottleUnit) (interface{}, interface{}) {
	if v == nil {
		return nil, nil
	}
	var us string
	if u != nil {
		us = string(*u)
	}
	return *v, us
}

// AddUserTrafficUsed increases traffic_used_bytes for a user.
func (s *Store) AddUserTrafficUsed(userID string, delta int64) error {
	if delta <= 0 {
		return nil
	}
	_, err := s.db.Exec(`UPDATE vpn_users SET traffic_used_bytes = traffic_used_bytes + ?, last_seen_unix = ? WHERE id=?`,
		delta, time.Now().Unix(), userID)
	return err
}

// InsertUserTrafficSnapshot stores a point for dashboard charts.
func (s *Store) InsertUserTrafficSnapshot(ts int64, userID, protocol string, upBytes, downBytes int64) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO user_traffic_snapshots(ts,user_id,protocol,up_bytes,down_bytes) VALUES(?,?,?,?,?)`,
		ts, userID, protocol, upBytes, downBytes)
	return err
}

type TrafficSnapRow struct {
	Timestamp int64
	Protocol  string
	UpBytes   int64
	DownBytes int64
}

func (s *Store) UserTrafficSnapshots(userID string, fromTs int64) ([]TrafficSnapRow, error) {
	rows, err := s.db.Query(`SELECT ts, protocol, up_bytes, down_bytes FROM user_traffic_snapshots WHERE user_id=? AND ts>=? ORDER BY ts ASC`,
		userID, fromTs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficSnapRow
	for rows.Next() {
		var r TrafficSnapRow
		if err := rows.Scan(&r.Timestamp, &r.Protocol, &r.UpBytes, &r.DownBytes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
