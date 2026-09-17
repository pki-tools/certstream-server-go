package certstream

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// CPUCapacity describes how much CPU this process can actually use.
//
// The distinction matters: a container limited to one core still reports every
// host core through runtime.NumCPU, and Go did not make GOMAXPROCS aware of
// cgroup quotas until 1.25. On older runtimes the scheduler happily spreads
// across more threads than the quota allows, so utilisation pins at the quota
// while looking like a fraction of the machine.
type CPUCapacity struct {
	NumCPU     int
	GOMAXPROCS int
	// Limit is the effective core count: the cgroup quota when one is set,
	// otherwise GOMAXPROCS.
	Limit float64
	// QuotaSource names where a limit came from, empty when unrestricted.
	QuotaSource string
	// Mismatch is true when a quota is set below GOMAXPROCS, which is the
	// configuration that misleads and that wastes scheduling effort.
	Mismatch bool
}

// DetectCPUCapacity inspects the runtime and any cgroup CPU quota.
func DetectCPUCapacity() CPUCapacity {
	c := CPUCapacity{
		NumCPU:     runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	}

	c.Limit = float64(c.GOMAXPROCS)

	if quota, source, ok := cgroupCPUQuota(); ok && quota > 0 {
		c.QuotaSource = source
		c.Limit = quota

		if quota < float64(c.GOMAXPROCS) {
			c.Mismatch = true
		}
	}

	return c
}

// cgroupCPUQuota reads the CPU quota in cores, checking cgroup v2 then v1.
func cgroupCPUQuota() (cores float64, source string, ok bool) {
	// cgroup v2: "<quota> <period>", or "max <period>" when unrestricted.
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		fields := strings.Fields(strings.TrimSpace(string(data)))
		if len(fields) == 2 && fields[0] != "max" {
			quota, qErr := strconv.ParseFloat(fields[0], 64)
			period, pErr := strconv.ParseFloat(fields[1], 64)

			if qErr == nil && pErr == nil && period > 0 {
				return quota / period, "cgroup v2", true
			}
		}
	}

	// cgroup v1: quota and period in separate files; -1 means unrestricted.
	quotaRaw, qErr := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	periodRaw, pErr := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")

	if qErr == nil && pErr == nil {
		quota, e1 := strconv.ParseFloat(strings.TrimSpace(string(quotaRaw)), 64)
		period, e2 := strconv.ParseFloat(strings.TrimSpace(string(periodRaw)), 64)

		if e1 == nil && e2 == nil && quota > 0 && period > 0 {
			return quota / period, "cgroup v1", true
		}
	}

	return 0, "", false
}

// Saturation converts CPU used, expressed as a percentage of one core, into a
// percentage of everything this process is allowed to use.
func (c CPUCapacity) Saturation(percentOfOneCore float64) float64 {
	if c.Limit <= 0 {
		return 0
	}

	return percentOfOneCore / c.Limit
}
