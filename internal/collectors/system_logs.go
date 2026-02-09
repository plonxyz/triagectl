package collectors

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type SystemLogsCollector struct{}

func (c *SystemLogsCollector) ID() string          { return "system_logs" }
func (c *SystemLogsCollector) Name() string        { return "System Logs & Crash Reports" }
func (c *SystemLogsCollector) Description() string { return "Collects system logs and crash reports" }
func (c *SystemLogsCollector) RequiresRoot() bool  { return false }

func (c *SystemLogsCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var artifacts []models.Artifact

	// User crash reports
	userCrashPath := filepath.Join(homeDir, "Library/Logs/DiagnosticReports")
	crashArtifacts := c.collectLogFiles(userCrashPath, "user_crash_report", hostname)
	artifacts = append(artifacts, crashArtifacts...)

	// System crash reports (may require root)
	systemCrashPath := "/Library/Logs/DiagnosticReports"
	systemCrashArtifacts := c.collectLogFiles(systemCrashPath, "system_crash_report", hostname)
	artifacts = append(artifacts, systemCrashArtifacts...)

	// Install logs
	installLogPath := "/var/log/install.log"
	if info, err := os.Stat(installLogPath); err == nil {
		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "install_log",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"path":     installLogPath,
				"size":     info.Size(),
				"mod_time": info.ModTime().Format(time.RFC3339),
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: true,
				SourcePath:   installLogPath,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}
		artifacts = append(artifacts, artifact)
	}

	return artifacts, nil
}

func (c *SystemLogsCollector) collectLogFiles(logDir, logType, hostname string) []models.Artifact {
	var artifacts []models.Artifact

	entries, err := os.ReadDir(logDir)
	if err != nil {
		return artifacts
	}

	// Get recent logs (last 7 days)
	cutoff := time.Now().Add(-7 * 24 * time.Hour)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fullPath := filepath.Join(logDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Only collect recent logs
		if info.ModTime().Before(cutoff) {
			continue
		}

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: logType,
			Hostname:     hostname,
			Data: map[string]interface{}{
				"filename": entry.Name(),
				"path":     fullPath,
				"size":     info.Size(),
				"mod_time": info.ModTime().Format(time.RFC3339),
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				SourcePath:   fullPath,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts
}
