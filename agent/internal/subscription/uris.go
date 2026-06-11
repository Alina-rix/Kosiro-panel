package subscription

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"kosiro/agent/internal/models"
)

// BuildVLESSURI builds a vless:// link from protocol preset config.
func BuildVLESSURI(host string, port int, userUUID string, pr models.Protocol) string {
	cfg := pr.Config
	network := strFromCfg(cfg, "transport", "tcp")
	security := strFromCfg(cfg, "security", "none")
	flow := strFromCfg(cfg, "flow", "")
	mux := cfgBool(cfg, "mux", false)
	reality := security == "reality"

	switch pr.Type {
	case models.ProtoVLESSReality, models.ProtoVLESSRealityXHTTP, models.ProtoVLESSRealityTLSMux:
		reality = true
		if flow == "" {
			flow = "xtls-rprx-vision"
		}
		if pr.Type == models.ProtoVLESSRealityTLSMux {
			mux = true
		}
	case models.ProtoVLESSXHTTP:
		network = "xhttp"
	}

	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("type", network)
	if flow != "" {
		q.Set("flow", flow)
	}
	if mux {
		q.Set("mux", "1")
	}
	if network == "xhttp" {
		q.Set("path", strFromCfg(cfg, "xhttp_path", "/"))
		if mode := strFromCfg(cfg, "xhttp_mode", ""); mode != "" {
			q.Set("mode", mode)
		}
	}
	if reality {
		sni := strFromCfg(cfg, "sni", "www.cloudflare.com")
		pbk := strFromCfg(cfg, "public_key", "")
		sid := strFromCfg(cfg, "short_id", "")
		if sid == "" && len(getStrSlice(cfg, "short_ids")) > 0 {
			sid = getStrSlice(cfg, "short_ids")[0]
		}
		q.Set("security", "reality")
		q.Set("sni", sni)
		q.Set("fp", strFromCfg(cfg, "fingerprint", "chrome"))
		q.Set("pbk", pbk)
		q.Set("sid", sid)
	} else if sec := strFromCfg(cfg, "security", strFromCfg(cfg, "tls_security", "none")); sec != "" && sec != "none" && sec != "reality" {
		q.Set("security", sec)
		if sni := strFromCfg(cfg, "sni", host); sni != "" {
			q.Set("sni", sni)
		}
	}

	label := url.QueryEscape(strFromCfg(cfg, "remark", pr.DisplayName))
	if label == "" {
		label = "Kosiro-VLESS"
	}
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", userUUID, host, port, q.Encode(), label)
}

func BuildTUICURI(uuid, password, host string, port int, sni, cc string) string {
	q := url.Values{}
	q.Set("congestion_control", cc)
	q.Set("alpn", "h3")
	if sni != "" {
		q.Set("sni", sni)
	}
	q.Set("insecure", "1")
	suffix := "?" + q.Encode()
	return fmt.Sprintf("tuic://%s:%s@%s:%d%s#%s", uuid, url.PathEscape(password), host, port, suffix, url.QueryEscape("Kosiro-TUIC"))
}

func BuildAnyTLSURI(password, host string, port int, sni string) string {
	q := url.Values{}
	q.Set("security", "tls")
	q.Set("insecure", "1")
	if sni != "" {
		q.Set("sni", sni)
	}
	return fmt.Sprintf("anytls://%s@%s:%d?%s#%s", url.PathEscape(password), host, port, q.Encode(), url.QueryEscape("Kosiro-AnyTLS"))
}

func getStrSlice(m map[string]interface{}, k string) []string {
	v, ok := m[k]
	if !ok {
		return nil
	}
	if s, ok := v.([]interface{}); ok {
		out := make([]string, 0, len(s))
		for _, x := range s {
			out = append(out, fmt.Sprint(x))
		}
		return out
	}
	return nil
}

func cfgBool(m map[string]interface{}, k string, def bool) bool {
	if v, ok := m[k]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

func BuildVMessURI(host string, port int, userUUID, network string) string {
	if network == "" {
		network = "tcp"
	}
	// vmess:// base64 json simplified for generic clients
	payload := fmt.Sprintf(`{"v":"2","ps":"Kosiro-VMess","add":"%s","port":%d,"id":"%s","aid":"0","net":"%s","type":"none","host":"","path":"","tls":""}`,
		host, port, userUUID, network)
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))
}

func BuildSSURI(method, password, host string, port int) string {
	user := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
	return fmt.Sprintf("ss://%s@%s:%d#%s", user, host, port, url.QueryEscape("Kosiro-SS"))
}

func BuildTrojanURI(password, host string, port int) string {
	return fmt.Sprintf("trojan://%s@%s:%d?security=tls#%s", url.PathEscape(password), host, port, url.QueryEscape("Kosiro-Trojan"))
}

func BuildHysteria2URI(password, host string, port int, sni string) string {
	q := url.Values{}
	if sni != "" {
		q.Set("sni", sni)
	}
	suffix := ""
	if enc := q.Encode(); enc != "" {
		suffix = "?" + enc
	}
	return fmt.Sprintf("hysteria2://%s@%s:%d%s#%s", url.PathEscape(password), host, port, suffix, url.QueryEscape("Kosiro-Hy2"))
}

func BuildMTProtoURI(host string, port int, secret string) string {
	return fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s", host, port, url.QueryEscape(secret))
}

// EncodeSubscriptionBase64 joins URIs and returns base64 (standard v2rayN/Happ style).
func EncodeSubscriptionBase64(uris []string) string {
	joined := strings.Join(uris, "\n")
	return base64.StdEncoding.EncodeToString([]byte(joined))
}

// CollectURIsForUser builds all share links for enabled installed protocols.
func CollectURIsForUser(publicHost string, protos []models.Protocol, u models.VPNUser) []string {
	var out []string
	for _, pr := range protos {
		if !pr.Installed || !pr.Enabled {
			continue
		}
		if !contains(u.EnabledProtocolIDs, pr.ID) {
			continue
		}
		switch pr.Type {
		case models.ProtoVLESS, models.ProtoVLESSReality, models.ProtoVLESSXHTTP, models.ProtoVLESSRealityXHTTP, models.ProtoVLESSRealityTLSMux:
			port := intFromCfg(pr.Config, "port", 443)
			out = append(out, BuildVLESSURI(publicHost, port, u.UUID, pr))
		case models.ProtoVMess:
			port := intFromCfg(pr.Config, "port", 10086)
			netw := strFromCfg(pr.Config, "network", "tcp")
			out = append(out, BuildVMessURI(publicHost, port, u.UUID, netw))
		case models.ProtoShadowsocks:
			port := intFromCfg(pr.Config, "port", 8388)
			method := strFromCfg(pr.Config, "method", "2022-blake3-aes-256-gcm")
			out = append(out, BuildSSURI(method, u.UUID, publicHost, port))
		case models.ProtoTrojan:
			port := intFromCfg(pr.Config, "port", 8444)
			out = append(out, BuildTrojanURI(u.UUID, publicHost, port))
		case models.ProtoHysteria2:
			port := intFromCfg(pr.Config, "port", 8445)
			sni := strFromCfg(pr.Config, "sni", publicHost)
			out = append(out, BuildHysteria2URI(u.UUID, publicHost, port, sni))
		case models.ProtoTUIC:
			port := intFromCfg(pr.Config, "port", 8447)
			sni := strFromCfg(pr.Config, "sni", publicHost)
			cc := strFromCfg(pr.Config, "congestion_control", "bbr")
			out = append(out, BuildTUICURI(u.UUID, u.UUID, publicHost, port, sni, cc))
		case models.ProtoAnyTLS:
			port := intFromCfg(pr.Config, "port", 8448)
			sni := strFromCfg(pr.Config, "sni", publicHost)
			out = append(out, BuildAnyTLSURI(u.UUID, publicHost, port, sni))
		case models.ProtoMTProto:
			port := intFromCfg(pr.Config, "port", 8446)
			sec := strFromCfg(pr.Config, "secret", "")
			if sec != "" {
				out = append(out, BuildMTProtoURI(publicHost, port, sec))
			}
		case models.ProtoAmneziaWG:
			// AWG: clients use Amnezia; provide vpn:// or conf snippet in API separately
			out = append(out, fmt.Sprintf("# Kosiro AmneziaWG: import .conf from user export in app (peer %s)", u.Name))
		}
	}
	return out
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
		return fmt.Sprint(v)
	}
	return def
}
