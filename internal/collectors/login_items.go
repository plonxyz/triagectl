package collectors

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type LoginItemsCollector struct{}

func (c *LoginItemsCollector) ID() string          { return "login_items" }
func (c *LoginItemsCollector) Name() string        { return "Login Items" }
func (c *LoginItemsCollector) Description() string { return "Collects login items and background task management entries" }
func (c *LoginItemsCollector) RequiresRoot() bool  { return false }

func (c *LoginItemsCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	var artifacts []models.Artifact

	// Try sfltool dumpbtm (macOS 13+)
	artifacts = append(artifacts, c.collectBTM(ctx, hostname)...)

	// Try backgrounditems.btm via plutil
	artifacts = append(artifacts, c.collectBackgroundItems(hostname)...)

	return artifacts, nil
}

func (c *LoginItemsCollector) collectBTM(ctx context.Context, hostname string) []models.Artifact {
	var artifacts []models.Artifact

	out, err := exec.CommandContext(ctx, "sfltool", "dumpbtm").CombinedOutput()
	if err != nil {
		return artifacts
	}

	lines := strings.Split(string(out), "\n")
	var currentItem map[string]interface{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			if currentItem != nil && len(currentItem) > 0 {
				artifacts = append(artifacts, models.Artifact{
					Timestamp:    time.Now(),
					CollectorID:  c.ID(),
					ArtifactType: "login_item_btm",
					Hostname:     hostname,
					Data:         currentItem,
					Metadata: models.ArtifactMetadata{
						Success:     true,
						CollectedAt: time.Now().Format(time.RFC3339),
					},
				})
				currentItem = nil
			}
			continue
		}

		if strings.Contains(line, ":") {
			if currentItem == nil {
				currentItem = make(map[string]interface{})
			}
			parts := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(parts[0])
			val := ""
			if len(parts) > 1 {
				val = strings.TrimSpace(parts[1])
			}
			currentItem[key] = val
		}
	}

	// Flush last item
	if currentItem != nil && len(currentItem) > 0 {
		artifacts = append(artifacts, models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "login_item_btm",
			Hostname:     hostname,
			Data:         currentItem,
			Metadata: models.ArtifactMetadata{
				Success:     true,
				CollectedAt: time.Now().Format(time.RFC3339),
			},
		})
	}

	return artifacts
}

func (c *LoginItemsCollector) collectBackgroundItems(hostname string) []models.Artifact {
	var artifacts []models.Artifact

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return artifacts
	}

	btmPaths := []string{
		filepath.Join(homeDir, "Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"),
	}

	for _, btmPath := range btmPaths {
		if _, err := os.Stat(btmPath); err != nil {
			continue
		}

		out, err := exec.Command("plutil", "-convert", "xml1", "-o", "-", btmPath).CombinedOutput()
		if err != nil {
			continue
		}

		artifacts = append(artifacts, models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "login_item_backgrounditems",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"path":    btmPath,
				"content": string(out),
			},
			Metadata: models.ArtifactMetadata{
				Success:    true,
				SourcePath: btmPath,
				CollectedAt: time.Now().Format(time.RFC3339),
			},
		})
	}

	return artifacts
}
