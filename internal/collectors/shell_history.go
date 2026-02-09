package collectors

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type ShellHistoryCollector struct{}

func (c *ShellHistoryCollector) ID() string          { return "shell_history" }
func (c *ShellHistoryCollector) Name() string        { return "Shell History" }
func (c *ShellHistoryCollector) Description() string { return "Collects bash and zsh command history" }
func (c *ShellHistoryCollector) RequiresRoot() bool  { return false }

func (c *ShellHistoryCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var artifacts []models.Artifact

	// Bash history
	bashHistory := filepath.Join(homeDir, ".bash_history")
	bashArtifacts := c.collectHistory(bashHistory, "bash_history", hostname)
	artifacts = append(artifacts, bashArtifacts...)

	// Zsh history
	zshHistory := filepath.Join(homeDir, ".zsh_history")
	zshArtifacts := c.collectHistory(zshHistory, "zsh_history", hostname)
	artifacts = append(artifacts, zshArtifacts...)

	return artifacts, nil
}

func (c *ShellHistoryCollector) collectHistory(historyPath, historyType, hostname string) []models.Artifact {
	var artifacts []models.Artifact

	file, err := os.Open(historyPath)
	if err != nil {
		return artifacts
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		if line == "" {
			continue
		}

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: historyType,
			Hostname:     hostname,
			Data: map[string]interface{}{
				"command":     line,
				"line_number": lineNum,
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				SourcePath:   historyPath,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts
}
