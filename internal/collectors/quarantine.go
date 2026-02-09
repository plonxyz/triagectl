package collectors

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/plonxyz/triagectl/internal/models"
)

type QuarantineEventsCollector struct{}

func (c *QuarantineEventsCollector) ID() string          { return "quarantine_events" }
func (c *QuarantineEventsCollector) Name() string        { return "Quarantine Events" }
func (c *QuarantineEventsCollector) Description() string { return "Collects macOS quarantine events (downloaded files)" }
func (c *QuarantineEventsCollector) RequiresRoot() bool  { return false }

func (c *QuarantineEventsCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var artifacts []models.Artifact

	// Quarantine events database
	quarantineDB := filepath.Join(homeDir, "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")

	if _, err := os.Stat(quarantineDB); os.IsNotExist(err) {
		return artifacts, nil
	}

	// Copy database to avoid lock issues
	tmpDB := filepath.Join(os.TempDir(), "quarantine_copy.db")
	defer os.Remove(tmpDB)

	input, err := os.ReadFile(quarantineDB)
	if err != nil {
		return artifacts, nil
	}

	if err := os.WriteFile(tmpDB, input, 0600); err != nil {
		return artifacts, nil
	}

	db, err := sql.Open("sqlite3", tmpDB)
	if err != nil {
		return artifacts, nil
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT
			LSQuarantineEventIdentifier,
			LSQuarantineTimeStamp,
			LSQuarantineAgentName,
			LSQuarantineAgentBundleIdentifier,
			LSQuarantineDataURLString,
			LSQuarantineOriginURLString
		FROM LSQuarantineEvent
		ORDER BY LSQuarantineTimeStamp DESC
	`)
	if err != nil {
		return artifacts, nil
	}
	defer rows.Close()

	for rows.Next() {
		var eventID, agentName, agentBundle, dataURL, originURL string
		var timestamp float64

		if err := rows.Scan(&eventID, &timestamp, &agentName, &agentBundle, &dataURL, &originURL); err != nil {
			continue
		}

		// macOS stores time as Mac absolute time (seconds since 2001-01-01)
		macEpoch := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
		eventTime := macEpoch.Add(time.Duration(timestamp) * time.Second)

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "quarantine_event",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"event_id":      eventID,
				"timestamp":     eventTime.Format(time.RFC3339),
				"agent_name":    agentName,
				"agent_bundle":  agentBundle,
				"data_url":      dataURL,
				"origin_url":    originURL,
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				SourcePath:   quarantineDB,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts, nil
}
