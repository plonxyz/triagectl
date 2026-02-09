package collectors

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type FirewallCollector struct{}

func (c *FirewallCollector) ID() string          { return "firewall" }
func (c *FirewallCollector) Name() string        { return "Firewall Status" }
func (c *FirewallCollector) Description() string { return "Collects macOS Application Firewall configuration" }
func (c *FirewallCollector) RequiresRoot() bool  { return false }

func (c *FirewallCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	var artifacts []models.Artifact

	fwPath := "/usr/libexec/ApplicationFirewall/socketfilterfw"

	data := make(map[string]interface{})

	// Global state
	if out, err := exec.CommandContext(ctx, fwPath, "--getglobalstate").CombinedOutput(); err == nil {
		status := strings.TrimSpace(string(out))
		data["global_state"] = status
		data["enabled"] = strings.Contains(strings.ToLower(status), "enabled")
	}

	// Stealth mode
	if out, err := exec.CommandContext(ctx, fwPath, "--getstealthmode").CombinedOutput(); err == nil {
		status := strings.TrimSpace(string(out))
		data["stealth_mode"] = status
		data["stealth_enabled"] = strings.Contains(strings.ToLower(status), "enabled")
	}

	// Block all incoming
	if out, err := exec.CommandContext(ctx, fwPath, "--getblockall").CombinedOutput(); err == nil {
		data["block_all"] = strings.TrimSpace(string(out))
	}

	// Allowed apps
	if out, err := exec.CommandContext(ctx, fwPath, "--listapps").CombinedOutput(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		var apps []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				apps = append(apps, line)
			}
		}
		data["allowed_apps"] = apps
		data["allowed_app_count"] = len(apps)
	}

	if len(data) > 0 {
		artifacts = append(artifacts, models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "firewall_status",
			Hostname:     hostname,
			Data:         data,
			Metadata: models.ArtifactMetadata{
				Success:     true,
				CollectedAt: time.Now().Format(time.RFC3339),
			},
		})
	}

	return artifacts, nil
}
