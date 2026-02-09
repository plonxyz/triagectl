package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

// TimelineEntry represents a single event in Timesketch-conformant format.
// The four mandatory Timesketch fields are message, datetime, timestamp, and timestamp_desc.
type TimelineEntry struct {
	Message       string                 `json:"message"`
	Datetime      string                 `json:"datetime"`
	Timestamp     int64                  `json:"timestamp"`
	TimestampDesc string                 `json:"timestamp_desc"`
	CollectorID   string                 `json:"collector_id"`
	ArtifactType  string                 `json:"artifact_type"`
	Hostname      string                 `json:"hostname"`
	RiskScore     int                    `json:"risk_score,omitempty"`
	Data          map[string]interface{} `json:"data"`
}

// GenerateTimeline creates a timeline.csv from collected artifacts in Timesketch CSV format.
func GenerateTimeline(artifacts []models.Artifact, outputPath string, summarize func(models.Artifact) string) error {
	var entries []TimelineEntry

	for _, a := range artifacts {
		et := resolveEventTime(a)
		msg := ""
		if summarize != nil {
			msg = summarize(a)
		}

		entries = append(entries, TimelineEntry{
			Message:       msg,
			Datetime:      et.UTC().Format(time.RFC3339),
			Timestamp:     et.UnixMicro(),
			TimestampDesc: timestampDesc(a.ArtifactType),
			CollectorID:   a.CollectorID,
			ArtifactType:  a.ArtifactType,
			Hostname:      a.Hostname,
			RiskScore:     a.RiskScore,
			Data:          a.Data,
		})
	}

	// Sort chronologically by timestamp (microsecond epoch)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp < entries[j].Timestamp
	})

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	w := csv.NewWriter(file)
	defer w.Flush()

	// Write header row — Timesketch mandatory fields first
	header := []string{"message", "datetime", "timestamp", "timestamp_desc", "collector_id", "artifact_type", "hostname", "risk_score", "data"}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, e := range entries {
		dataJSON, _ := json.Marshal(e.Data)
		row := []string{
			e.Message,
			e.Datetime,
			fmt.Sprintf("%d", e.Timestamp),
			e.TimestampDesc,
			e.CollectorID,
			e.ArtifactType,
			e.Hostname,
			fmt.Sprintf("%d", e.RiskScore),
			string(dataJSON),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// timestampDesc maps artifact types to Timesketch timestamp descriptions.
func timestampDesc(artifactType string) string {
	at := strings.ToLower(artifactType)
	switch {
	case at == "safari_history" || at == "chrome_history":
		return "Browser Visit"
	case strings.HasSuffix(at, "launch_agent") || strings.HasSuffix(at, "launch_daemon"):
		return "Persistence Modified"
	case at == "running_process":
		return "Process Running"
	case at == "network_connection" || at == "open_network_file":
		return "Network Connection"
	case at == "recent_file":
		return "File Accessed"
	case at == "bash_history" || at == "zsh_history":
		return "Command Executed"
	case at == "quarantine_event":
		return "File Downloaded"
	case strings.HasPrefix(at, "unified_log_"):
		return "Log Entry"
	case at == "user_crash_report" || at == "system_crash_report":
		return "Crash Report"
	case at == "install_log":
		return "Software Installed"
	case strings.HasSuffix(at, "_status"):
		return "Security Status Collected"
	default:
		return "Event Logged"
	}
}

// resolveEventTime determines the best event time for an artifact
func resolveEventTime(a models.Artifact) time.Time {
	// Priority 1: explicit EventTime
	if a.EventTime != nil {
		return *a.EventTime
	}

	// Priority 2: known time fields in Data
	timeFields := []string{"visit_time", "last_visit_time", "mod_time", "timestamp", "event_time", "last_modified", "modified", "created"}
	for _, field := range timeFields {
		if v, ok := a.Data[field]; ok {
			if s, ok := v.(string); ok {
				for _, layout := range []string{
					time.RFC3339,
					"2006-01-02T15:04:05.000Z",
					"2006-01-02 15:04:05",
					time.RFC3339Nano,
				} {
					if t, err := time.Parse(layout, s); err == nil {
						return t
					}
				}
			}
		}
	}

	// Priority 3: collection timestamp
	return a.Timestamp
}
