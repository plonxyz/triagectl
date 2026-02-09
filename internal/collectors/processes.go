package collectors

import (
	"context"
	"os"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/plonxyz/triagectl/internal/models"
)

type RunningProcessesCollector struct{}

func (c *RunningProcessesCollector) ID() string          { return "running_processes" }
func (c *RunningProcessesCollector) Name() string        { return "Running Processes" }
func (c *RunningProcessesCollector) Description() string { return "Collects all running processes" }
func (c *RunningProcessesCollector) RequiresRoot() bool  { return false }

func (c *RunningProcessesCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()

	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var artifacts []models.Artifact

	for _, p := range procs {
		name, _ := p.Name()
		exe, _ := p.Exe()
		cmdline, _ := p.Cmdline()
		username, _ := p.Username()
		cwd, _ := p.Cwd()
		ppid, _ := p.Ppid()
		createTime, _ := p.CreateTime()
		cpuPercent, _ := p.CPUPercent()
		memPercent, _ := p.MemoryPercent()
		memInfo, _ := p.MemoryInfo()
		connections, _ := p.Connections()

		var memRSS uint64
		if memInfo != nil {
			memRSS = memInfo.RSS
		}

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "running_process",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"pid":              p.Pid,
				"ppid":             ppid,
				"name":             name,
				"exe":              exe,
				"cmdline":          cmdline,
				"username":         username,
				"cwd":              cwd,
				"create_time":      time.Unix(createTime/1000, 0).Format(time.RFC3339),
				"cpu_percent":      cpuPercent,
				"memory_percent":   memPercent,
				"memory_rss_bytes": memRSS,
				"num_connections":  len(connections),
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts, nil
}
