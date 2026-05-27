package xray

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// QueryStats pulls Xray StatsService counters from apiBase (e.g. http://127.0.0.1:10085).
func QueryStats(apiBase string) (map[string]int64, error) {
	if apiBase == "" {
		apiBase = "http://127.0.0.1:10085"
	}
	apiBase = strings.TrimSuffix(apiBase, "/")
	body := map[string]interface{}{
		"pattern": "",
		"reset":   false,
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, apiBase+"/stats/query", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xray stats: %s: %s", resp.Status, string(raw))
	}
	var parsed struct {
		Stat []*struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	out := make(map[string]int64)
	for _, s := range parsed.Stat {
		if s != nil {
			out[s.Name] = s.Value
		}
	}
	return out, nil
}
