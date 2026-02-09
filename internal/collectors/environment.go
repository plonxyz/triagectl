package collectors

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type EnvironmentCollector struct{}

func (c *EnvironmentCollector) ID() string          { return "environment" }
func (c *EnvironmentCollector) Name() string        { return "Environment Variables" }
func (c *EnvironmentCollector) Description() string { return "Collects environment variables and flags suspicious ones" }
func (c *EnvironmentCollector) RequiresRoot() bool  { return false }

// suspiciousVars are environment variables commonly abused for persistence or injection
var suspiciousVars = map[string]string{
	"DYLD_INSERT_LIBRARIES":  "Dynamic library injection",
	"DYLD_LIBRARY_PATH":      "Library path override",
	"DYLD_FRAMEWORK_PATH":    "Framework path override",
	"DYLD_FALLBACK_LIBRARY_PATH": "Fallback library path override",
	"LD_PRELOAD":             "Library preload (Linux-style, unusual on macOS)",
	"BASH_ENV":               "Bash startup script override",
	"ENV":                    "Shell startup script override",
	"PROMPT_COMMAND":         "Command executed before each prompt",
	"http_proxy":             "HTTP proxy setting",
	"https_proxy":            "HTTPS proxy setting",
	"ALL_PROXY":              "Global proxy setting",
}

func (c *EnvironmentCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	var artifacts []models.Artifact

	for _, envVar := range os.Environ() {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		data := map[string]interface{}{
			"key":   key,
			"value": value,
		}

		suspicious := false
		if reason, ok := suspiciousVars[key]; ok {
			suspicious = true
			data["suspicious"] = true
			data["suspicious_reason"] = reason
		}

		// Also flag any DYLD_ variables not in the list
		if !suspicious && strings.HasPrefix(key, "DYLD_") {
			suspicious = true
			data["suspicious"] = true
			data["suspicious_reason"] = "DYLD environment variable override"
		}

		artifactType := "env_variable"
		if suspicious {
			artifactType = "env_variable_suspicious"
		}

		artifacts = append(artifacts, models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: artifactType,
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
