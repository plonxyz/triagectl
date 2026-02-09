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

type ExtensionsCollector struct{}

func (c *ExtensionsCollector) ID() string          { return "extensions" }
func (c *ExtensionsCollector) Name() string        { return "System/Kernel Extensions" }
func (c *ExtensionsCollector) Description() string { return "Collects system extensions, kernel extensions, and third-party extensions" }
func (c *ExtensionsCollector) RequiresRoot() bool  { return false }

func (c *ExtensionsCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	var artifacts []models.Artifact

	// System extensions
	artifacts = append(artifacts, c.collectSystemExtensions(ctx, hostname)...)

	// Kernel extensions
	artifacts = append(artifacts, c.collectKernelExtensions(ctx, hostname)...)

	// /Library/Extensions directory
	artifacts = append(artifacts, c.collectLibraryExtensions(hostname)...)

	return artifacts, nil
}

func (c *ExtensionsCollector) collectSystemExtensions(ctx context.Context, hostname string) []models.Artifact {
	var artifacts []models.Artifact

	out, err := exec.CommandContext(ctx, "systemextensionsctl", "list").CombinedOutput()
	if err != nil {
		return artifacts
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "System Extension") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		data := map[string]interface{}{
			"raw_line": line,
		}

		// Try to parse known fields
		for i, f := range fields {
			if strings.Contains(f, ".") && i == 0 {
				data["identifier"] = f
			}
			if f == "[activated" || f == "[enabled]" || f == "enabled]" {
				data["state"] = "enabled"
			}
			if strings.HasPrefix(f, "(") && strings.HasSuffix(f, ")") {
				data["version"] = strings.Trim(f, "()")
			}
		}

		artifacts = append(artifacts, models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "system_extension",
			Hostname:     hostname,
			Data:         data,
			Metadata: models.ArtifactMetadata{
				Success:     true,
				CollectedAt: time.Now().Format(time.RFC3339),
			},
		})
	}

	return artifacts
}

func (c *ExtensionsCollector) collectKernelExtensions(ctx context.Context, hostname string) []models.Artifact {
	var artifacts []models.Artifact

	out, err := exec.CommandContext(ctx, "kextstat", "-l").CombinedOutput()
	if err != nil {
		return artifacts
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Index") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		data := map[string]interface{}{
			"raw_line": line,
		}

		// Typical kextstat format: Index Refs Address Size Wired Name (Version)
		if len(fields) >= 6 {
			data["index"] = fields[0]
			data["refs"] = fields[1]
			data["address"] = fields[2]
			data["size"] = fields[3]
			data["wired"] = fields[4]
			data["name"] = fields[5]
		}
		if len(fields) >= 7 {
			data["version"] = strings.Trim(fields[6], "()")
		}

		artifacts = append(artifacts, models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "kernel_extension",
			Hostname:     hostname,
			Data:         data,
			Metadata: models.ArtifactMetadata{
				Success:     true,
				CollectedAt: time.Now().Format(time.RFC3339),
			},
		})
	}

	return artifacts
}

func (c *ExtensionsCollector) collectLibraryExtensions(hostname string) []models.Artifact {
	var artifacts []models.Artifact

	extDir := "/Library/Extensions"
	entries, err := os.ReadDir(extDir)
	if err != nil {
		return artifacts
	}

	for _, entry := range entries {
		fullPath := filepath.Join(extDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		artifacts = append(artifacts, models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "library_extension",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"name":     entry.Name(),
				"path":     fullPath,
				"is_dir":   entry.IsDir(),
				"size":     info.Size(),
				"mod_time": info.ModTime().Format(time.RFC3339),
			},
			Metadata: models.ArtifactMetadata{
				Success:    true,
				SourcePath: fullPath,
				CollectedAt: time.Now().Format(time.RFC3339),
			},
		})
	}

	return artifacts
}
