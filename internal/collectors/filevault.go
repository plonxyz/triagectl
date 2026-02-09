package collectors

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type FileVaultCollector struct{}

func (c *FileVaultCollector) ID() string          { return "filevault" }
func (c *FileVaultCollector) Name() string        { return "FileVault Status" }
func (c *FileVaultCollector) Description() string { return "Collects FileVault disk encryption status" }
func (c *FileVaultCollector) RequiresRoot() bool  { return false }

func (c *FileVaultCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	var artifacts []models.Artifact

	// fdesetup status
	if a := c.collectFDESetup(ctx, hostname); a != nil {
		artifacts = append(artifacts, *a)
	}

	// diskutil apfs list
	if a := c.collectAPFS(ctx, hostname); a != nil {
		artifacts = append(artifacts, *a)
	}

	return artifacts, nil
}

func (c *FileVaultCollector) collectFDESetup(ctx context.Context, hostname string) *models.Artifact {
	out, err := exec.CommandContext(ctx, "fdesetup", "status").CombinedOutput()
	if err != nil {
		// fdesetup may fail without root but still gives status
		if len(out) == 0 {
			return nil
		}
	}

	status := strings.TrimSpace(string(out))
	enabled := strings.Contains(status, "FileVault is On")

	return &models.Artifact{
		Timestamp:    time.Now(),
		CollectorID:  c.ID(),
		ArtifactType: "filevault_status",
		Hostname:     hostname,
		Data: map[string]interface{}{
			"raw_status": status,
			"enabled":    enabled,
		},
		Metadata: models.ArtifactMetadata{
			Success:     true,
			CollectedAt: time.Now().Format(time.RFC3339),
		},
	}
}

func (c *FileVaultCollector) collectAPFS(ctx context.Context, hostname string) *models.Artifact {
	out, err := exec.CommandContext(ctx, "diskutil", "apfs", "list").CombinedOutput()
	if err != nil {
		if len(out) == 0 {
			return nil
		}
	}

	content := string(out)
	encrypted := strings.Contains(content, "FileVault:") && strings.Contains(content, "Yes")

	// Count volumes
	volumeCount := strings.Count(content, "APFS Volume")

	return &models.Artifact{
		Timestamp:    time.Now(),
		CollectorID:  c.ID(),
		ArtifactType: "apfs_encryption",
		Hostname:     hostname,
		Data: map[string]interface{}{
			"raw_output":   content,
			"encrypted":    encrypted,
			"volume_count": volumeCount,
		},
		Metadata: models.ArtifactMetadata{
			Success:     true,
			CollectedAt: time.Now().Format(time.RFC3339),
		},
	}
}
