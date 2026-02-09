package collectors

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type FSEventsCollector struct{}

func (c *FSEventsCollector) ID() string          { return "fsevents" }
func (c *FSEventsCollector) Name() string        { return "FSEvents File System Changes" }
func (c *FSEventsCollector) Description() string { return "Collects recent file system events using fs_usage" }
func (c *FSEventsCollector) RequiresRoot() bool  { return true }

func (c *FSEventsCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	var artifacts []models.Artifact

	// Run fs_usage for 5 seconds to capture recent filesystem activity.
	// fs_usage is a streaming tool that never exits on its own, so we use
	// Start + manual pipe reading instead of Output() to avoid hanging.
	timeout := 5 * time.Second
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "fs_usage", "-w", "-f", "filesystem")
	// Force pipe closure shortly after the process is killed, preventing
	// hangs from inherited file descriptors.
	cmd.WaitDelay = 2 * time.Second

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return artifacts, nil
	}

	if err := cmd.Start(); err != nil {
		return artifacts, nil
	}

	scanner := bufio.NewScanner(stdout)
	maxEvents := 200
	count := 0

	for scanner.Scan() && count < maxEvents {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "TIMESTAMP") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "fs_event",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"raw_event": line,
				"operation": fields[0],
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: true,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
		count++
	}

	// Wait for process cleanup; ignore the error since the context
	// cancellation killing fs_usage is expected behavior.
	cmd.Wait()

	return artifacts, nil
}
