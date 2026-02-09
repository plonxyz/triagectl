package collectors

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type LaunchAgentsCollector struct{}

func (c *LaunchAgentsCollector) ID() string          { return "launch_agents" }
func (c *LaunchAgentsCollector) Name() string        { return "Launch Agents/Daemons" }
func (c *LaunchAgentsCollector) Description() string { return "Collects persistence mechanisms via Launch Agents and Daemons" }
func (c *LaunchAgentsCollector) RequiresRoot() bool  { return false }

func (c *LaunchAgentsCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()

	// Standard locations for launch agents/daemons
	locations := []struct {
		path        string
		itemType    string
		requiresRoot bool
	}{
		{"/Library/LaunchAgents", "system_launch_agent", false},
		{"/Library/LaunchDaemons", "system_launch_daemon", true},
		{"/System/Library/LaunchAgents", "system_launch_agent", false},
		{"/System/Library/LaunchDaemons", "system_launch_daemon", false},
	}

	// Add user-specific locations
	homeDir, err := os.UserHomeDir()
	if err == nil {
		locations = append(locations, struct {
			path        string
			itemType    string
			requiresRoot bool
		}{filepath.Join(homeDir, "Library/LaunchAgents"), "user_launch_agent", false})
	}

	var artifacts []models.Artifact

	for _, loc := range locations {
		items, err := os.ReadDir(loc.path)
		if err != nil {
			continue // Directory might not exist or not accessible
		}

		for _, item := range items {
			if item.IsDir() {
				continue
			}

			fullPath := filepath.Join(loc.path, item.Name())
			info, err := item.Info()
			if err != nil {
				continue
			}

			artifact := models.Artifact{
				Timestamp:    time.Now(),
				CollectorID:  c.ID(),
				ArtifactType: loc.itemType,
				Hostname:     hostname,
				Data: map[string]interface{}{
					"name":      item.Name(),
					"path":      fullPath,
					"size":      info.Size(),
					"mod_time":  info.ModTime().Format(time.RFC3339),
					"directory": loc.path,
				},
				Metadata: models.ArtifactMetadata{
					Success:      true,
					RequiresRoot: loc.requiresRoot,
					SourcePath:   fullPath,
					CollectedAt:  time.Now().Format(time.RFC3339),
				},
			}

			artifacts = append(artifacts, artifact)
		}
	}

	return artifacts, nil
}
