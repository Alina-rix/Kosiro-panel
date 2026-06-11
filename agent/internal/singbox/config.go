package singbox

import (
	"encoding/json"
	"os"
	"path/filepath"

	"kosiro/agent/internal/models"
)

// WriteConfig writes sing-box JSON with all installed sing-box inbounds (Hy2, TUIC, AnyTLS).
func WriteConfig(dataDir string, protos []models.Protocol, users []models.VPNUser) error {
	var inbounds []map[string]interface{}

	for _, pr := range protos {
		if !pr.Installed || !pr.Enabled {
			continue
		}
		switch pr.Type {
		case models.ProtoHysteria2:
			if ib := hysteria2Inbound(pr, users); ib != nil {
				inbounds = append(inbounds, ib)
			}
		case models.ProtoTUIC:
			if ib := tuicInbound(pr, users); ib != nil {
				inbounds = append(inbounds, ib)
			}
		case models.ProtoAnyTLS:
			if ib := anyTLSInbound(pr, users); ib != nil {
				inbounds = append(inbounds, ib)
			}
		}
	}

	if len(inbounds) == 0 {
		inbounds = append(inbounds, placeholderHy2())
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{"level": "info"},
		"inbounds": inbounds,
		"outbounds": []map[string]interface{}{
			{"type": "direct", "tag": "direct"},
		},
	}

	dir := filepath.Join(dataDir, "singbox")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600)
}

func hysteria2Inbound(proto models.Protocol, users []models.VPNUser) map[string]interface{} {
	port := intFromCfg(proto.Config, "port", 8445)
	sni := strFromCfg(proto.Config, "sni", "")
	clients := singboxUsers(proto.ID, users, "password")
	return map[string]interface{}{
		"type":        "hysteria2",
		"tag":         "hy2-in",
		"listen":      "::",
		"listen_port": port,
		"users":       clients,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
			"insecure":    true,
		},
	}
}

func tuicInbound(proto models.Protocol, users []models.VPNUser) map[string]interface{} {
	port := intFromCfg(proto.Config, "port", 8447)
	sni := strFromCfg(proto.Config, "sni", "")
	cc := strFromCfg(proto.Config, "congestion_control", "bbr")
	var tuicUsers []map[string]interface{}
	for _, u := range users {
		if !contains(u.EnabledProtocolIDs, proto.ID) {
			continue
		}
		tuicUsers = append(tuicUsers, map[string]interface{}{
			"name":     u.Name,
			"uuid":     u.UUID,
			"password": u.UUID,
		})
	}
	if len(tuicUsers) == 0 {
		tuicUsers = append(tuicUsers, map[string]interface{}{"name": "placeholder", "uuid": "00000000-0000-0000-0000-000000000099", "password": "kosiro-placeholder"})
	}
	return map[string]interface{}{
		"type":               "tuic",
		"tag":                "tuic-in",
		"listen":             "::",
		"listen_port":        port,
		"users":              tuicUsers,
		"congestion_control": cc,
		"zero_rtt_handshake": false,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
			"insecure":    true,
			"alpn":        []string{"h3"},
		},
	}
}

func anyTLSInbound(proto models.Protocol, users []models.VPNUser) map[string]interface{} {
	port := intFromCfg(proto.Config, "port", 8448)
	sni := strFromCfg(proto.Config, "sni", "")
	var anyUsers []map[string]interface{}
	for _, u := range users {
		if !contains(u.EnabledProtocolIDs, proto.ID) {
			continue
		}
		anyUsers = append(anyUsers, map[string]interface{}{
			"name":     u.Name,
			"password": u.UUID,
		})
	}
	if len(anyUsers) == 0 {
		anyUsers = append(anyUsers, map[string]interface{}{"name": "placeholder", "password": "kosiro-placeholder"})
	}
	return map[string]interface{}{
		"type":        "anytls",
		"tag":         "anytls-in",
		"listen":      "::",
		"listen_port": port,
		"users":       anyUsers,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
			"insecure":    true,
		},
	}
}

func singboxUsers(protoID string, users []models.VPNUser, passField string) []map[string]interface{} {
	var clients []map[string]interface{}
	for _, u := range users {
		if !contains(u.EnabledProtocolIDs, protoID) {
			continue
		}
		clients = append(clients, map[string]interface{}{
			"name":     u.Name,
			passField:  u.UUID,
		})
	}
	if len(clients) == 0 {
		clients = append(clients, map[string]interface{}{"name": "placeholder", passField: "kosiro-placeholder"})
	}
	return clients
}

func placeholderHy2() map[string]interface{} {
	return map[string]interface{}{
		"type":        "hysteria2",
		"tag":         "hy2-in",
		"listen":      "::",
		"listen_port": 8445,
		"users":       []map[string]interface{}{{"name": "placeholder", "password": "kosiro-placeholder"}},
		"tls":         map[string]interface{}{"enabled": true, "insecure": true},
	}
}

func contains(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func intFromCfg(m map[string]interface{}, k string, def int) int {
	if v, ok := m[k]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return def
}

func strFromCfg(m map[string]interface{}, k, def string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// WriteHysteria2 keeps backward compatibility for callers.
func WriteHysteria2(dataDir string, proto models.Protocol, users []models.VPNUser) error {
	return WriteConfig(dataDir, []models.Protocol{proto}, users)
}
