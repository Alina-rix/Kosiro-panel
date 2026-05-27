package mtproto

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteEnvFile writes a small env file consumed by docker-compose for MTProto proxy.
func WriteEnvFile(dataDir string, port int, secret, sponsor string, public bool) error {
	dir := filepath.Join(dataDir, "mtproto")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf("MTPROTO_PORT=%d\nMTPROTO_SECRET=%s\nMTPROTO_SPONSOR=%s\nMTPROTO_PUBLIC=%t\n",
		port, secret, sponsor, public)
	return os.WriteFile(filepath.Join(dir, ".env"), []byte(content), 0o600)
}
