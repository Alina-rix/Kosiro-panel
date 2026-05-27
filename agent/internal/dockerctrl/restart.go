package dockerctrl

import (
	"os/exec"
	"path/filepath"
)

// RestartXray runs `docker compose restart xray` in composeDir (optional).
func RestartXray(composeDir string) error {
	if composeDir == "" {
		return nil
	}
	cmd := exec.Command("docker", "compose", "-f", filepath.Join(composeDir, "docker-compose.yml"), "restart", "xray")
	cmd.Dir = composeDir
	return cmd.Run()
}

// ComposeUpDetached runs docker compose up -d.
func ComposeUpDetached(composeDir string) error {
	if composeDir == "" {
		return nil
	}
	cmd := exec.Command("docker", "compose", "-f", filepath.Join(composeDir, "docker-compose.yml"), "up", "-d")
	cmd.Dir = composeDir
	return cmd.Run()
}
