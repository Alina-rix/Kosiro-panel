package subscription

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"kosiro/agent/internal/models"
)

// BuildVLESSRealityURI returns a vless:// share link.
func BuildVLESSRealityURI(host string, port int, userUUID, sni, pbk, sid, flow, fp, network string) string {
	if flow == "" {
		flow = "xtls-rprx-vision"
	}
	if fp == "" {
		fp = "chrome"
	}
	if network == "" {
		network = "tcp"
	}
	if sid == "" {
		sid = ""
	}
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("flow", flow)
	q.Set("security", "reality")
	q.Set("sni", sni)
	q.Set("fp", fp)
	q.Set("pbk", pbk)
	q.Set("sid", sid)
	q.Set("type", network)
	// spx optional
	u := fmt.Sprintf("vless://%s@%s:%d?%s#%s", userUUID, host, port, q.Encode(), url.QueryEscape("Kosiro-VLESS"))
	return u
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
		case models.ProtoVLESSReality:
			port := intFromCfg(pr.Config, "port", 443)
			sni := strFromCfg(pr.Config, "sni", "www.cloudflare.com")
			pbk := strFromCfg(pr.Config, "public_key", "bmXOCF3Sc8P_im1gOKasqnDhnjqm7BQkhM0cuhVvmPs")
			sid := strFromCfg(pr.Config, "short_id", "")
			flow := strFromCfg(pr.Config, "flow", "xtls-rprx-vision")
			fp := strFromCfg(pr.Config, "fingerprint", "chrome")
			netw := strFromCfg(pr.Config, "network", "tcp")
			out = append(out, BuildVLESSRealityURI(publicHost, port, u.UUID, sni, pbk, sid, flow, fp, netw))
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
