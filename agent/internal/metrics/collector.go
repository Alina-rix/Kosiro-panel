package metrics

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"

	"kosiro/agent/internal/db"
	"kosiro/agent/internal/models"
)

type Store interface {
	InsertMetrics(ts int64, cpu, ram, netUp, netDown, disk float64) error
}

type Collector struct {
	store      Store
	lastNetUp  uint64
	lastNetDown uint64
	lastNetTS  time.Time
}

func NewCollector(s *db.Store) *Collector {
	return &Collector{store: s}
}

func (c *Collector) Snapshot() (models.SystemMetrics, error) {
	var m models.SystemMetrics
	m.Timestamp = time.Now().Unix()

	pct, err := cpu.Percent(500*time.Millisecond, false)
	if err == nil && len(pct) > 0 {
		m.CPUPercent = pct[0]
	}

	vm, err := mem.VirtualMemory()
	if err == nil {
		m.RAMPercent = vm.UsedPercent
		m.RAMUsedBytes = vm.Used
		m.RAMTotalBytes = vm.Total
	}

	du, err := disk.Usage("/")
	if err == nil {
		m.DiskPercent = du.UsedPercent
		m.DiskUsedBytes = du.Used
		m.DiskTotalBytes = du.Total
	}

	now := time.Now()
	io, err := net.IOCounters(false)
	if err == nil && len(io) > 0 {
		up := io[0].BytesSent
		down := io[0].BytesRecv
		if !c.lastNetTS.IsZero() {
			dt := now.Sub(c.lastNetTS).Seconds()
			if dt > 0 {
				m.NetUpBps = float64(up-c.lastNetUp) / dt * 8
				m.NetDownBps = float64(down-c.lastNetDown) / dt * 8
			}
		}
		c.lastNetUp = up
		c.lastNetDown = down
		c.lastNetTS = now
	}

	return m, nil
}

func (c *Collector) RunBackground(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			snap, err := c.Snapshot()
			if err != nil {
				continue
			}
			_ = c.store.InsertMetrics(snap.Timestamp, snap.CPUPercent, snap.RAMPercent, snap.NetUpBps, snap.NetDownBps, snap.DiskPercent)
		}
	}
}
