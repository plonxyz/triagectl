package collectors

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/host"
	"github.com/plonxyz/triagectl/internal/models"
)

type SystemInfoCollector struct{}

func (c *SystemInfoCollector) ID() string          { return "system_info" }
func (c *SystemInfoCollector) Name() string        { return "System Information" }
func (c *SystemInfoCollector) Description() string { return "Collects basic system information" }
func (c *SystemInfoCollector) RequiresRoot() bool  { return false }

func (c *SystemInfoCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()

	info, err := host.Info()
	if err != nil {
		return nil, err
	}

	// Get macOS version details
	osVersion := c.getMacOSVersion()
	buildVersion := c.getBuildVersion()
	serialNumber := c.getSerialNumber()

	artifact := models.Artifact{
		Timestamp:    time.Now(),
		CollectorID:  c.ID(),
		ArtifactType: "system_info",
		Hostname:     hostname,
		Data: map[string]interface{}{
			"hostname":       hostname,
			"os":             info.OS,
			"platform":       info.Platform,
			"platform_family": info.PlatformFamily,
			"platform_version": info.PlatformVersion,
			"macos_version":  osVersion,
			"build_version":  buildVersion,
			"kernel_version": info.KernelVersion,
			"kernel_arch":    info.KernelArch,
			"uptime_seconds": info.Uptime,
			"boot_time":      time.Unix(int64(info.BootTime), 0).Format(time.RFC3339),
			"procs":          info.Procs,
			"architecture":   runtime.GOARCH,
			"num_cpus":       runtime.NumCPU(),
			"serial_number":  serialNumber,
		},
		Metadata: models.ArtifactMetadata{
			Success:      true,
			RequiresRoot: false,
			CollectedAt:  time.Now().Format(time.RFC3339),
		},
	}

	return []models.Artifact{artifact}, nil
}

func (c *SystemInfoCollector) getMacOSVersion() string {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func (c *SystemInfoCollector) getBuildVersion() string {
	cmd := exec.Command("sw_vers", "-buildVersion")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func (c *SystemInfoCollector) getSerialNumber() string {
	cmd := exec.Command("system_profiler", "SPHardwareDataType")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Serial Number") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
