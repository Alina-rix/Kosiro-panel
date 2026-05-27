package statsync

import (
	"context"
	"log"
	"strings"
	"time"

	"kosiro/agent/internal/db"
	"kosiro/agent/internal/models"
	"kosiro/agent/internal/xray"
)

// Worker periodically reads Xray stats and updates usage + snapshots.
type Worker struct {
	Store      *db.Store
	APIBase    string
	Interval   time.Duration
	lastTotals map[string]int64 // stat name -> value
}

func New(s *db.Store, apiBase string) *Worker {
	return &Worker{
		Store:      s,
		APIBase:    apiBase,
		Interval:   2 * time.Minute,
		lastTotals: map[string]int64{},
	}
}

func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.tick(); err != nil {
				log.Printf("statsync: %v", err)
			}
		}
	}
}

type trafficDelta struct {
	up   int64
	down int64
}

func (w *Worker) tick() error {
	stats, err := xray.QueryStats(w.APIBase)
	if err != nil {
		return err
	}
	users, err := w.Store.ListUsers()
	if err != nil {
		return err
	}
	uuidToID := map[string]string{}
	legacyEmailToID := map[string]string{}
	for _, u := range users {
		uuidToID[strings.ToLower(u.UUID)] = u.ID
		em := u.Email
		if em == "" {
			em = u.UUID + "@kosiro.local"
		}
		legacyEmailToID[strings.ToLower(em)] = u.ID
	}

	now := time.Now().Unix()
	perUserProto := map[string]map[string]trafficDelta{}

	for name, val := range stats {
		email, direction, ok := parseUserTrafficStat(name)
		if !ok {
			continue
		}
		prev, seen := w.lastTotals[name]
		if !seen {
			w.lastTotals[name] = val
			continue
		}
		delta := val - prev
		w.lastTotals[name] = val
		if delta <= 0 {
			continue
		}

		userID, proto := resolveUserAndProtocol(email, uuidToID, legacyEmailToID)
		if userID == "" {
			continue
		}
		if perUserProto[userID] == nil {
			perUserProto[userID] = map[string]trafficDelta{}
		}
		td := perUserProto[userID][proto]
		switch direction {
		case "uplink":
			td.up += delta
		case "downlink":
			td.down += delta
		}
		perUserProto[userID][proto] = td
	}

	for userID, byProto := range perUserProto {
		var total int64
		for proto, td := range byProto {
			total += td.up + td.down
			if td.up+td.down <= 0 {
				continue
			}
			_ = w.Store.RecordProtocolUsage(userID, proto, now)
			_ = w.Store.InsertUserTrafficSnapshot(now, userID, proto, td.up, td.down)
		}
		if total > 0 {
			if err := w.Store.AddUserTrafficUsed(userID, total); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseUserTrafficStat extracts email and direction from Xray counter names like
// user>>>email>>>traffic>>>uplink.
func parseUserTrafficStat(name string) (email, direction string, ok bool) {
	if !strings.Contains(name, "user>>>") || !strings.Contains(name, ">>>traffic>>>") {
		return "", "", false
	}
	parts := strings.Split(name, ">>>")
	if len(parts) < 4 {
		return "", "", false
	}
	direction = parts[len(parts)-1]
	if direction != "uplink" && direction != "downlink" {
		return "", "", false
	}
	return strings.ToLower(parts[1]), direction, true
}

func resolveUserAndProtocol(email string, uuidToID, legacyEmailToID map[string]string) (userID, proto string) {
	if id, ok := legacyEmailToID[email]; ok {
		return id, string(models.ProtoVLESSReality)
	}
	local, _, found := strings.Cut(email, "@")
	if !found {
		return "", ""
	}
	uuidPart, protoPart, hasProto := strings.Cut(local, "+")
	if hasProto && protoPart != "" {
		if id, ok := uuidToID[uuidPart]; ok {
			return id, protoPart
		}
	}
	if id, ok := uuidToID[local]; ok {
		return id, string(models.ProtoVLESSReality)
	}
	return "", ""
}
