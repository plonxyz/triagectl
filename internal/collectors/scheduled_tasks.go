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

type ScheduledTasksCollector struct{}

func (c *ScheduledTasksCollector) ID() string          { return "scheduled_tasks" }
func (c *ScheduledTasksCollector) Name() string        { return "Scheduled Tasks (Cron)" }
func (c *ScheduledTasksCollector) Description() string { return "Collects cron jobs and scheduled tasks" }
func (c *ScheduledTasksCollector) RequiresRoot() bool  { return false }

func (c *ScheduledTasksCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var artifacts []models.Artifact

	// User crontab
	cmd := exec.Command("crontab", "-l")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			artifact := models.Artifact{
				Timestamp:    time.Now(),
				CollectorID:  c.ID(),
				ArtifactType: "user_crontab",
				Hostname:     hostname,
				Data: map[string]interface{}{
					"line_number": i + 1,
					"entry":       line,
					"user":        os.Getenv("USER"),
				},
				Metadata: models.ArtifactMetadata{
					Success:      true,
					RequiresRoot: false,
					CollectedAt:  time.Now().Format(time.RFC3339),
				},
			}

			artifacts = append(artifacts, artifact)
		}
	}

	// System crontabs (may require root)
	systemCronPaths := []string{
		"/etc/crontab",
		"/etc/cron.d",
		"/etc/periodic/daily",
		"/etc/periodic/weekly",
		"/etc/periodic/monthly",
	}

	for _, cronPath := range systemCronPaths {
		cronArtifacts := c.collectCronFiles(cronPath, hostname)
		artifacts = append(artifacts, cronArtifacts...)
	}

	// User periodic tasks
	userPeriodic := filepath.Join(homeDir, ".periodic")
	if info, err := os.Stat(userPeriodic); err == nil && info.IsDir() {
		periodicArtifacts := c.collectCronFiles(userPeriodic, hostname)
		artifacts = append(artifacts, periodicArtifacts...)
	}

	// at jobs (atq command)
	cmd = exec.Command("atq")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			artifact := models.Artifact{
				Timestamp:    time.Now(),
				CollectorID:  c.ID(),
				ArtifactType: "at_job",
				Hostname:     hostname,
				Data: map[string]interface{}{
					"entry": line,
				},
				Metadata: models.ArtifactMetadata{
					Success:      true,
					RequiresRoot: false,
					CollectedAt:  time.Now().Format(time.RFC3339),
				},
			}

			artifacts = append(artifacts, artifact)
		}
	}

	return artifacts, nil
}

func (c *ScheduledTasksCollector) collectCronFiles(cronPath, hostname string) []models.Artifact {
	var artifacts []models.Artifact

	info, err := os.Stat(cronPath)
	if err != nil {
		return artifacts
	}

	if info.IsDir() {
		// Directory - read all files
		entries, err := os.ReadDir(cronPath)
		if err != nil {
			return artifacts
		}

		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}

			fullPath := filepath.Join(cronPath, entry.Name())
			content, err := os.ReadFile(fullPath)
			if err != nil {
				continue
			}

			lines := strings.Split(string(content), "\n")
			for i, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				artifact := models.Artifact{
					Timestamp:    time.Now(),
					CollectorID:  c.ID(),
					ArtifactType: "system_cron",
					Hostname:     hostname,
					Data: map[string]interface{}{
						"file":        entry.Name(),
						"path":        fullPath,
						"line_number": i + 1,
						"entry":       line,
					},
					Metadata: models.ArtifactMetadata{
						Success:      true,
						RequiresRoot: true,
						SourcePath:   fullPath,
						CollectedAt:  time.Now().Format(time.RFC3339),
					},
				}

				artifacts = append(artifacts, artifact)
			}
		}
	} else {
		// Single file
		content, err := os.ReadFile(cronPath)
		if err != nil {
			return artifacts
		}

		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			artifact := models.Artifact{
				Timestamp:    time.Now(),
				CollectorID:  c.ID(),
				ArtifactType: "system_cron",
				Hostname:     hostname,
				Data: map[string]interface{}{
					"path":        cronPath,
					"line_number": i + 1,
					"entry":       line,
				},
				Metadata: models.ArtifactMetadata{
					Success:      true,
					RequiresRoot: true,
					SourcePath:   cronPath,
					CollectedAt:  time.Now().Format(time.RFC3339),
				},
			}

			artifacts = append(artifacts, artifact)
		}
	}

	return artifacts
}
