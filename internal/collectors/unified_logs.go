package collectors

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type UnifiedLogsCollector struct{}

func (c *UnifiedLogsCollector) ID() string          { return "unified_logs" }
func (c *UnifiedLogsCollector) Name() string        { return "Unified Logs" }
func (c *UnifiedLogsCollector) Description() string { return "Collects recent unified log entries" }
func (c *UnifiedLogsCollector) RequiresRoot() bool  { return false }

// logEntry represents a single entry from `log show --style json`
type logEntry struct {
	Timestamp        string `json:"timestamp"`
	EventMessage     string `json:"eventMessage"`
	MessageType      string `json:"messageType"`
	ProcessImagePath string `json:"processImagePath"`
	SenderImagePath  string `json:"senderImagePath"`
	Subsystem        string `json:"subsystem"`
	Category         string `json:"category"`
	ProcessID        int    `json:"processID"`
}

func (c *UnifiedLogsCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	var artifacts []models.Artifact

	predicates := []struct {
		name      string
		predicate string
	}{
		{"security", `eventMessage CONTAINS "authentication" OR eventMessage CONTAINS "login" OR eventMessage CONTAINS "sudo"`},
		{"network", `eventMessage CONTAINS "connection" OR eventMessage CONTAINS "network" OR process == "mDNSResponder"`},
		{"process", `eventMessage CONTAINS "exec" OR eventMessage CONTAINS "spawn" OR process == "kernel"`},
		{"errors", `messageType == error OR messageType == fault`},
	}

	for _, pred := range predicates {
		cmd := exec.CommandContext(ctx, "log", "show",
			"--style", "json",
			"--last", "1h",
			"--predicate", pred.predicate,
		)

		output, err := cmd.Output()
		if err != nil {
			continue
		}

		var entries []logEntry
		if err := json.Unmarshal(output, &entries); err != nil {
			continue
		}

		maxLogs := 100
		if len(entries) > maxLogs {
			entries = entries[len(entries)-maxLogs:]
		}

		for _, entry := range entries {
			process := filepath.Base(entry.ProcessImagePath)

			// Parse timestamp for EventTime
			var eventTime *time.Time
			if entry.Timestamp != "" {
				for _, layout := range []string{
					"2006-01-02 15:04:05.000000-0700",
					"2006-01-02 15:04:05.000000+0000",
					time.RFC3339,
				} {
					if t, err := time.Parse(layout, entry.Timestamp); err == nil {
						eventTime = &t
						break
					}
				}
			}

			artifact := models.Artifact{
				Timestamp:    time.Now(),
				CollectorID:  c.ID(),
				ArtifactType: "unified_log_" + pred.name,
				Hostname:     hostname,
				EventTime:    eventTime,
				Data: map[string]interface{}{
					"category":      pred.name,
					"event_message": entry.EventMessage,
					"message_type":  entry.MessageType,
					"process":       process,
					"process_path":  entry.ProcessImagePath,
					"subsystem":     entry.Subsystem,
					"pid":           entry.ProcessID,
					"timestamp":     entry.Timestamp,
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
