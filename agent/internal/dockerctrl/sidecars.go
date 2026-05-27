package dockerctrl

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"kosiro/agent/internal/models"
)

// SyncSidecars starts optional compose profiles (sing-box, MTProto) based on installed protocols.
func SyncSidecars(composeDir, dataDir string, protos []models.Protocol) error {
	if composeDir == "" {
		return nil
	}
	composeFile := filepath.Join(composeDir, "docker-compose.yml")
	if _, err := os.Stat(composeFile); err != nil {
		return nil
	}

	needFull := false
	needMTProto := false
	for _, p := range protos {
		if !p.Installed {
			continue
		}
		switch p.Type {
		case models.ProtoHysteria2:
			needFull = true
		case models.ProtoMTProto:
			needMTProto = true
		}
	}

	envPath := filepath.Join(composeDir, ".env")
	if needMTProto {
		if err := mergeMTProtoEnv(envPath, filepath.Join(dataDir, "mtproto", ".env")); err != nil {
			return err
		}
	}

	args := []string{"compose", "-f", composeFile, "--env-file", envPath}
	if needFull {
		args = append(args, "--profile", "full")
	}
	if needMTProto {
		args = append(args, "--profile", "mtproto")
	}
	args = append(args, "up", "-d")

	cmd := exec.Command("docker", args...)
	cmd.Dir = composeDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("compose sidecars: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func mergeMTProtoEnv(composeEnv, mtprotoEnv string) error {
	vars := map[string]string{}
	if b, err := os.ReadFile(composeEnv); err == nil {
		parseEnvLines(string(b), vars)
	}
	if b, err := os.ReadFile(mtprotoEnv); err == nil {
		parseEnvLines(string(b), vars)
	}
	port := vars["MTPROTO_PORT"]
	if port == "" {
		port = "8446"
	}
	secret := vars["MTPROTO_SECRET"]
	sponsor := vars["MTPROTO_SPONSOR"]
	var sb strings.Builder
	if existing, err := os.ReadFile(composeEnv); err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(existing)))
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "MTPROTO_") || strings.HasPrefix(line, "MTPROTO_SECRET") {
				continue
			}
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
	}
	fmt.Fprintf(&sb, "MTPROTO_PORT=%s\nMTPROTO_SECRET=%s\nMTPROTO_SPONSOR=%s\n", port, secret, sponsor)
	return os.WriteFile(composeEnv, []byte(sb.String()), 0o600)
}

func parseEnvLines(raw string, out map[string]string) {
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			out[parts[0]] = parts[1]
		}
	}
}
