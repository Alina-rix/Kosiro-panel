package xray

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"kosiro/agent/internal/models"
)

// BuildConfig generates a minimal Xray JSON config with API, stats, and inbounds for enabled protocols.
func BuildConfig(publicHost string, protos []models.Protocol, users []models.VPNUser, apiListen string, logLevel string) (map[string]interface{}, error) {
	if logLevel == "" {
		logLevel = "warning"
	}
	if apiListen == "" {
		apiListen = "127.0.0.1:10085"
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": logLevel,
		},
		"api": map[string]interface{}{
			"tag":      "api",
			"services": []string{"StatsService", "HandlerService"},
		},
		"stats": struct{}{},
		"policy": map[string]interface{}{
			"levels": map[string]interface{}{
				"0": map[string]interface{}{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
			"system": map[string]interface{}{
				"statsInboundUplink":    true,
				"statsInboundDownlink":  true,
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
		},
		"routing": map[string]interface{}{
			"rules": []map[string]interface{}{
				{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
			},
		},
		"inbounds":  []interface{}{},
		"outbounds": []interface{}{},
	}

	inbounds := []interface{}{
		map[string]interface{}{
			"listen": apiListen,
			"port":   10085,
			"protocol": "dokodemo-door",
			"settings": map[string]interface{}{
				"address": "127.0.0.1",
			},
			"tag": "api",
		},
	}

	outbounds := []interface{}{
		map[string]interface{}{
			"protocol": "freedom",
			"tag":      "direct",
		},
		map[string]interface{}{
			"protocol": "blackhole",
			"tag":      "block",
		},
		map[string]interface{}{
			"protocol": "freedom",
			"tag":      "api",
		},
	}

	vlessPresets := []struct {
		typ  models.ProtocolType
		tag  string
		opts vlessInboundOpts
	}{
		{models.ProtoVLESSReality, "vless_reality", vlessInboundOpts{network: "tcp", reality: true, vision: true, defaultPort: 443}},
		{models.ProtoVLESSXHTTP, "vless_xhttp", vlessInboundOpts{network: "xhttp", defaultPort: 8440}},
		{models.ProtoVLESSRealityXHTTP, "vless_reality_xhttp", vlessInboundOpts{network: "xhttp", reality: true, vision: true, defaultPort: 8441}},
		{models.ProtoVLESSRealityTLSMux, "vless_reality_mux", vlessInboundOpts{network: "tcp", reality: true, vision: true, mux: true, defaultPort: 8442}},
	}
	for _, preset := range vlessPresets {
		pr := findProto(protos, preset.typ)
		if pr == nil || !pr.Enabled || !pr.Installed {
			continue
		}
		preset.opts.tag = preset.tag
		preset.opts.protoType = preset.typ
		if ib := buildVLESSInbound(*pr, users, preset.opts); ib != nil {
			inbounds = append(inbounds, ib)
		}
	}

	vmessProto := findProto(protos, models.ProtoVMess)
	if vmessProto != nil && vmessProto.Enabled && vmessProto.Installed {
		port := getInt(vmessProto.Config, "port", 10086)
		clients := []map[string]interface{}{}
		for _, u := range users {
			if !hasProto(u, vmessProto.ID) {
				continue
			}
			clients = append(clients, map[string]interface{}{
				"id":       u.UUID,
				"email":    StatsEmail(u.UUID, models.ProtoVMess),
				"alterId":  0,
				"security": "auto",
				"level":    0,
			})
		}
		if len(clients) == 0 {
			clients = append(clients, map[string]interface{}{"id": "00000000-0000-0000-0000-000000000002", "email": "placeholder@kosiro", "alterId": 0, "security": "auto", "level": 0})
		}
		inbounds = append(inbounds, map[string]interface{}{
			"listen":   "0.0.0.0",
			"port":     port,
			"protocol": "vmess",
			"settings": map[string]interface{}{
				"clients": clients,
			},
			"streamSettings": map[string]interface{}{
				"network":  getStr(vmessProto.Config, "network", "tcp"),
				"security": getStr(vmessProto.Config, "tls_security", "none"),
			},
			"tag": "vmess_in",
		})
	}

	ssProto := findProto(protos, models.ProtoShadowsocks)
	if ssProto != nil && ssProto.Enabled && ssProto.Installed {
		port := getInt(ssProto.Config, "port", 8388)
		method := getStr(ssProto.Config, "method", "2022-blake3-aes-256-gcm")
		password := getStr(ssProto.Config, "password", "change-me-kosiro")
		clients := []map[string]interface{}{}
		for _, u := range users {
			if !hasProto(u, ssProto.ID) {
				continue
			}
			clients = append(clients, map[string]interface{}{
				"method":   method,
				"password": u.UUID,
				"email":    StatsEmail(u.UUID, models.ProtoShadowsocks),
				"level":    0,
			})
		}
		if len(clients) == 0 {
			clients = append(clients, map[string]interface{}{"method": method, "password": password, "email": "placeholder@kosiro", "level": 0})
		}
		inbounds = append(inbounds, map[string]interface{}{
			"listen":   "0.0.0.0",
			"port":     port,
			"protocol": "shadowsocks",
			"settings": map[string]interface{}{
				"clients":    clients,
				"network":    "tcp,udp",
				"method":     method,
				"password":   password,
				"ivCheck":    true,
				"multiEmail": true,
			},
			"tag": "ss_in",
		})
	}

	trojanProto := findProto(protos, models.ProtoTrojan)
	if trojanProto != nil && trojanProto.Enabled && trojanProto.Installed {
		port := getInt(trojanProto.Config, "port", 8444)
		password := getStr(trojanProto.Config, "password", "kosiro-trojan")
		clients := []map[string]interface{}{}
		for _, u := range users {
			if !hasProto(u, trojanProto.ID) {
				continue
			}
			clients = append(clients, map[string]interface{}{
				"password": u.UUID,
				"email":    StatsEmail(u.UUID, models.ProtoTrojan),
				"level":    0,
			})
		}
		if len(clients) == 0 {
			clients = append(clients, map[string]interface{}{"password": password, "email": "placeholder@kosiro", "level": 0})
		}
		inbounds = append(inbounds, map[string]interface{}{
			"listen":   "0.0.0.0",
			"port":     port,
			"protocol": "trojan",
			"settings": map[string]interface{}{
				"clients": clients,
			},
			"streamSettings": map[string]interface{}{
				"network":  "tcp",
				"security": getStr(trojanProto.Config, "tls_security", "none"),
			},
			"tag": "trojan_in",
		})
	}

	cfg["inbounds"] = inbounds
	cfg["outbounds"] = outbounds
	_ = publicHost
	return cfg, nil
}

func WriteConfigFile(dataDir string, cfg map[string]interface{}) error {
	dir := filepath.Join(dataDir, "xray")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600)
}

func findProto(protos []models.Protocol, t models.ProtocolType) *models.Protocol {
	for i := range protos {
		if protos[i].Type == t && protos[i].Installed {
			return &protos[i]
		}
	}
	for i := range protos {
		if protos[i].Type == t {
			return &protos[i]
		}
	}
	return nil
}

func hasProto(u models.VPNUser, protoID string) bool {
	for _, id := range u.EnabledProtocolIDs {
		if id == protoID {
			return true
		}
	}
	return false
}

func getInt(m map[string]interface{}, k string, def int) int {
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

func getStr(m map[string]interface{}, k, def string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}
	return def
}

func getStrSlice(m map[string]interface{}, k string) []string {
	v, ok := m[k]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(s))
		for _, x := range s {
			out = append(out, fmt.Sprint(x))
		}
		return out
	case []string:
		return s
	default:
		return nil
	}
}

type vlessInboundOpts struct {
	tag         string
	protoType   models.ProtocolType
	network     string
	reality     bool
	vision      bool
	mux         bool
	defaultPort int
}

func buildVLESSInbound(pr models.Protocol, users []models.VPNUser, opts vlessInboundOpts) map[string]interface{} {
	port := getInt(pr.Config, "port", opts.defaultPort)
	network := opts.network
	if network == "" {
		network = getStr(pr.Config, "network", "tcp")
	}

	flow := ""
	if opts.vision {
		flow = getStr(pr.Config, "flow", "xtls-rprx-vision")
	}

	clients := []map[string]interface{}{}
	for _, u := range users {
		if !hasProto(u, pr.ID) {
			continue
		}
		c := map[string]interface{}{
			"id":    u.UUID,
			"email": StatsEmail(u.UUID, opts.protoType),
			"level": 0,
		}
		if flow != "" {
			c["flow"] = flow
		}
		clients = append(clients, c)
	}
	if len(clients) == 0 {
		ph := map[string]interface{}{"id": "00000000-0000-0000-0000-000000000001", "email": "placeholder@kosiro", "level": 0}
		if flow != "" {
			ph["flow"] = flow
		}
		clients = append(clients, ph)
	}

	stream := map[string]interface{}{"network": network}

	if network == "xhttp" {
		stream["xhttpSettings"] = map[string]interface{}{
			"path": getStr(pr.Config, "xhttp_path", "/"),
			"mode": getStr(pr.Config, "xhttp_mode", "auto"),
			"host": getStr(pr.Config, "xhttp_host", ""),
		}
	}

	if opts.reality {
		sni := getStr(pr.Config, "sni", "www.cloudflare.com")
		dest := getStr(pr.Config, "dest", sni+":443")
		pvk := getStr(pr.Config, "private_key", "")
		shortIDs := getStrSlice(pr.Config, "short_ids")
		if len(shortIDs) == 0 {
			if sid := getStr(pr.Config, "short_id", ""); sid != "" {
				shortIDs = []string{sid}
			} else {
				shortIDs = []string{""}
			}
		}
		stream["security"] = "reality"
		stream["realitySettings"] = map[string]interface{}{
			"show":        false,
			"dest":        dest,
			"xver":        0,
			"serverNames": []string{sni},
			"privateKey":  pvk,
			"shortIds":    shortIDs,
			"spiderX":     getStr(pr.Config, "spider_x", "/"),
			"fingerprint": getStr(pr.Config, "fingerprint", "chrome"),
		}
	} else if sec := getStr(pr.Config, "tls_security", "none"); sec != "" && sec != "none" {
		stream["security"] = sec
		if sec == "tls" {
			stream["tlsSettings"] = map[string]interface{}{
				"serverName": getStr(pr.Config, "sni", publicHostFrom(pr)),
			}
		}
	}

	return map[string]interface{}{
		"listen":   "0.0.0.0",
		"port":     port,
		"protocol": "vless",
		"settings": map[string]interface{}{
			"clients":    clients,
			"decryption": "none",
		},
		"streamSettings": stream,
		"sniffing": map[string]interface{}{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic"},
		},
		"tag": opts.tag,
	}
}

func publicHostFrom(pr models.Protocol) string {
	return getStr(pr.Config, "sni", "localhost")
}
