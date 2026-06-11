package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"kosiro/agent/internal/models"
)

// GenerateRealityKeyPair returns URL-safe base64 X25519 keys for REALITY.
func GenerateRealityKeyPair() (privateKey, publicKey string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	pub := priv.PublicKey()
	return base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		base64.RawURLEncoding.EncodeToString(pub.Bytes()), nil
}

// GenerateShortID returns a random 8-char hex shortId for REALITY.
func GenerateShortID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// EnsureRealityConfig fills private/public keys and short_id when missing.
func EnsureRealityConfig(cfg map[string]interface{}) error {
	if cfg == nil {
		return nil
	}
	if getStr(cfg, "private_key", "") == "" {
		priv, pub, err := GenerateRealityKeyPair()
		if err != nil {
			return err
		}
		cfg["private_key"] = priv
		cfg["public_key"] = pub
	}
	if getStr(cfg, "public_key", "") == "" {
		// legacy rows with only private_key
		cfg["public_key"] = getStr(cfg, "public_key", "")
	}
	if getStr(cfg, "short_id", "") == "" && len(getStrSlice(cfg, "short_ids")) == 0 {
		sid := GenerateShortID()
		cfg["short_id"] = sid
		cfg["short_ids"] = []interface{}{sid}
	}
	return nil
}

func UsesReality(t models.ProtocolType) bool {
	switch t {
	case models.ProtoVLESSReality, models.ProtoVLESSRealityXHTTP, models.ProtoVLESSRealityTLSMux:
		return true
	default:
		return false
	}
}
