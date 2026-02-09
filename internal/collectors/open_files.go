package collectors

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type OpenFilesCollector struct{}

func (c *OpenFilesCollector) ID() string          { return "open_files" }
func (c *OpenFilesCollector) Name() string        { return "Open Files (Network)" }
func (c *OpenFilesCollector) Description() string { return "Collects open network files and connections via lsof" }
func (c *OpenFilesCollector) RequiresRoot() bool  { return false }

func (c *OpenFilesCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	var artifacts []models.Artifact

	out, err := exec.CommandContext(ctx, "lsof", "-i", "-n", "-P").CombinedOutput()
	if err != nil {
		// lsof may exit non-zero but still produce output
		if len(out) == 0 {
			return nil, err
		}
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return artifacts, nil
	}

	// Parse header
	header := strings.Fields(lines[0])
	_ = header

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		data := map[string]interface{}{
			"command": fields[0],
			"pid":     fields[1],
			"user":    fields[2],
			"fd":      fields[3],
			"type":    fields[4],
			"device":  fields[5],
		}

		// Node and name fields may vary
		if len(fields) >= 8 {
			data["node"] = fields[7]
		}

		// The last field is typically the connection info
		name := fields[len(fields)-1]
		data["name"] = name

		// Parse connection details from name field
		if strings.Contains(name, "->") {
			parts := strings.SplitN(name, "->", 2)
			data["local_addr"] = parts[0]
			data["remote_addr"] = parts[1]
		} else if strings.Contains(name, ":") {
			data["listen_addr"] = name
		}

		// Extract state if present (ESTABLISHED, LISTEN, etc.)
		if len(fields) >= 10 {
			state := fields[len(fields)-1]
			if state == "(ESTABLISHED)" || state == "(LISTEN)" || state == "(CLOSE_WAIT)" ||
				state == "(TIME_WAIT)" || state == "(SYN_SENT)" {
				data["state"] = strings.Trim(state, "()")
				data["name"] = fields[len(fields)-2]
				if strings.Contains(fields[len(fields)-2], "->") {
					parts := strings.SplitN(fields[len(fields)-2], "->", 2)
					data["local_addr"] = parts[0]
					data["remote_addr"] = parts[1]
				}
			}
		}

		artifacts = append(artifacts, models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "open_network_file",
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
