package collectors

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type GatekeeperCollector struct{}

func (c *GatekeeperCollector) ID() string          { return "gatekeeper" }
func (c *GatekeeperCollector) Name() string        { return "Gatekeeper/XProtect/SIP" }
func (c *GatekeeperCollector) Description() string { return "Collects Gatekeeper, XProtect, and SIP security status" }
func (c *GatekeeperCollector) RequiresRoot() bool  { return false }

func (c *GatekeeperCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	var artifacts []models.Artifact

	// Gatekeeper status
	if a := c.collectGatekeeper(ctx, hostname); a != nil {
		artifacts = append(artifacts, *a)
	}

	// SIP status
	if a := c.collectSIP(ctx, hostname); a != nil {
		artifacts = append(artifacts, *a)
	}

	// XProtect version
	if a := c.collectXProtect(hostname); a != nil {
		artifacts = append(artifacts, *a)
	}

	return artifacts, nil
}

func (c *GatekeeperCollector) collectGatekeeper(ctx context.Context, hostname string) *models.Artifact {
	out, err := exec.CommandContext(ctx, "spctl", "--status").CombinedOutput()
	if err != nil {
		return nil
	}

	status := strings.TrimSpace(string(out))
	enabled := strings.Contains(status, "assessments enabled")

	return &models.Artifact{
		Timestamp:    time.Now(),
		CollectorID:  c.ID(),
		ArtifactType: "gatekeeper_status",
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

func (c *GatekeeperCollector) collectSIP(ctx context.Context, hostname string) *models.Artifact {
	out, err := exec.CommandContext(ctx, "csrutil", "status").CombinedOutput()
	if err != nil {
		return nil
	}

	status := strings.TrimSpace(string(out))
	enabled := strings.Contains(status, "enabled")

	return &models.Artifact{
		Timestamp:    time.Now(),
		CollectorID:  c.ID(),
		ArtifactType: "sip_status",
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

func (c *GatekeeperCollector) collectXProtect(hostname string) *models.Artifact {
	xprotectPaths := []string{
		"/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
		"/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
	}

	for _, plistPath := range xprotectPaths {
		if _, err := os.Stat(plistPath); err != nil {
			continue
		}

		out, err := exec.Command("plutil", "-convert", "xml1", "-o", "-", plistPath).CombinedOutput()
		if err != nil {
			continue
		}

		// Extract version from plist content
		content := string(out)
		version := extractPlistValue(content, "CFBundleShortVersionString")

		return &models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "xprotect_version",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"plist_path": plistPath,
				"version":    version,
				"raw_plist":  content,
			},
			Metadata: models.ArtifactMetadata{
				Success:    true,
				SourcePath: plistPath,
				CollectedAt: time.Now().Format(time.RFC3339),
			},
		}
	}

	return nil
}

func extractPlistValue(content, key string) string {
	idx := strings.Index(content, "<key>"+key+"</key>")
	if idx < 0 {
		return ""
	}
	rest := content[idx:]
	strStart := strings.Index(rest, "<string>")
	strEnd := strings.Index(rest, "</string>")
	if strStart < 0 || strEnd < 0 {
		return ""
	}
	return rest[strStart+8 : strEnd]
}
