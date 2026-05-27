package awg

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteServerHint stores operator notes for AmneziaWG 2 (host uses amneziawg-go or installer scripts).
func WriteServerHint(dataDir string, port int, preset string) error {
	dir := filepath.Join(dataDir, "awg")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	txt := fmt.Sprintf(`Kosiro AmneziaWG 2
Port: %d
Preset: %s

Deploy amneziawg-go or follow https://docs.amnezia.org/documentation/instructions/new-amneziawg-selfhosted
Kosiro will export peer configs via API (/v1/users/{id}/subscription) as .conf snippets in future releases.
Use Amnezia VPN client >= 4.8.12.9 for AWG 2.0 parameters.
`, port, preset)
	return os.WriteFile(filepath.Join(dir, "README.txt"), []byte(txt), 0o644)
}
