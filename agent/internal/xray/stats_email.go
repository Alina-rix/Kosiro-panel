package xray

import (
	"fmt"
	"strings"

	"kosiro/agent/internal/models"
)

// StatsEmail returns the Xray client email used for per-protocol traffic counters.
func StatsEmail(userUUID string, proto models.ProtocolType) string {
	return fmt.Sprintf("%s+%s@kosiro.local", strings.ToLower(userUUID), string(proto))
}
