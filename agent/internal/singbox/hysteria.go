package singbox

import (
	"encoding/json"
	"os"
	"path/filepath"

	"kosiro/agent/internal/models"
)

// WriteHysteria2 writes a minimal sing-box JSON with Hysteria2 inbound for Kosiro users.
func WriteHysteria2(dataDir string, proto models.Protocol, users []models.VPNUser) error {
	port := 8445
	if v, ok := proto.Config["port"].(float64); ok {
		port = int(v)
	}
	sni, _ := proto.Config["sni"].(string)

	inbounds := []map[string]interface{}{}
	clients := []map[string]interface{}{}
	for _, u := range users {
		if !contains(u.EnabledProtocolIDs, proto.ID) {
			continue
		}
		clients = append(clients, map[string]interface{}{
			"name":     u.Name,
			"password": u.UUID,
		})
	}
	if len(clients) == 0 {
		clients = append(clients, map[string]interface{}{"name": "placeholder", "password": "kosiro-placeholder"})
	}
	inbounds = append(inbounds, map[string]interface{}{
		"type":        "hysteria2",
		"tag":         "hy2-in",
		"listen":      "0.0.0.0",
		"listen_port": port,
		"users":       clients,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
			"insecure":    true,
		},
	})

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

func contains(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
