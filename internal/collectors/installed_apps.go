package collectors

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type InstalledAppsCollector struct{}

func (c *InstalledAppsCollector) ID() string          { return "installed_apps" }
func (c *InstalledAppsCollector) Name() string        { return "Installed Applications" }
func (c *InstalledAppsCollector) Description() string { return "Collects installed applications" }
func (c *InstalledAppsCollector) RequiresRoot() bool  { return false }

func (c *InstalledAppsCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()

	var artifacts []models.Artifact

	// System applications
	systemApps := c.collectApps("/Applications", "system_application", hostname)
	artifacts = append(artifacts, systemApps...)

	// User applications
	homeDir, err := os.UserHomeDir()
	if err == nil {
		userApps := c.collectApps(filepath.Join(homeDir, "Applications"), "user_application", hostname)
		artifacts = append(artifacts, userApps...)
	}

	return artifacts, nil
}

func (c *InstalledAppsCollector) collectApps(appDir, appType, hostname string) []models.Artifact {
	var artifacts []models.Artifact

	entries, err := os.ReadDir(appDir)
	if err != nil {
		return artifacts
	}

	for _, entry := range entries {
		if !entry.IsDir() || filepath.Ext(entry.Name()) != ".app" {
			continue
		}

		fullPath := filepath.Join(appDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: appType,
			Hostname:     hostname,
			Data: map[string]interface{}{
				"name":     entry.Name(),
				"path":     fullPath,
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
