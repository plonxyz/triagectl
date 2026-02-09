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

type KnowledgeCCollector struct{}

func (c *KnowledgeCCollector) ID() string          { return "knowledgec" }
func (c *KnowledgeCCollector) Name() string        { return "KnowledgeC Database" }
func (c *KnowledgeCCollector) Description() string { return "Collects app usage and screen time data" }
func (c *KnowledgeCCollector) RequiresRoot() bool  { return false }

func (c *KnowledgeCCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var artifacts []models.Artifact

	// KnowledgeC database location
	knowledgeDB := filepath.Join(homeDir, "Library/Application Support/Knowledge/knowledgeC.db")

	if _, err := os.Stat(knowledgeDB); os.IsNotExist(err) {
		return artifacts, nil
	}

	// Copy database to avoid lock issues
	tmpDB := filepath.Join(os.TempDir(), "knowledgec_copy.db")
	defer os.Remove(tmpDB)

	input, err := os.ReadFile(knowledgeDB)
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

	// Query app usage events
	// CAST to INTEGER to prevent go-sqlite3 from auto-converting TIMESTAMP columns to time.Time
	query := `
		SELECT
			ZOBJECT.ZVALUESTRING,
			CAST(ZOBJECT.ZSTARTDATE AS INTEGER),
			CAST(ZOBJECT.ZENDDATE AS INTEGER),
			CAST((ZOBJECT.ZENDDATE - ZOBJECT.ZSTARTDATE) AS INTEGER)
		FROM ZOBJECT
		WHERE ZOBJECT.ZSTREAMNAME = "/app/usage"
			AND ZOBJECT.ZVALUESTRING IS NOT NULL
		ORDER BY ZOBJECT.ZSTARTDATE DESC
	`

	rows, err := db.Query(query)
	if err != nil {
		return artifacts, nil
	}
	defer rows.Close()

	macEpoch := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

	for rows.Next() {
		var appName sql.NullString
		var startDate, endDate, duration interface{}

		if err := rows.Scan(&appName, &startDate, &endDate, &duration); err != nil {
			continue
		}
		if !appName.Valid || appName.String == "" {
			continue
		}

		data := map[string]interface{}{
			"app_name": appName.String,
		}

		if sd, ok := toSeconds(startDate); ok {
			data["start_time"] = macEpoch.Add(time.Duration(sd) * time.Second).Format(time.RFC3339)
		}
		if ed, ok := toSeconds(endDate); ok {
			data["end_time"] = macEpoch.Add(time.Duration(ed) * time.Second).Format(time.RFC3339)
		}
		if dur, ok := toSeconds(duration); ok && dur > 0 {
			data["duration_seconds"] = dur
		}

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "app_usage",
			Hostname:     hostname,
			Data:         data,
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				SourcePath:   knowledgeDB,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts, nil
}

func toSeconds(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case []byte:
		// sqlite3 driver sometimes returns []byte
		var i int64
		for _, b := range n {
			if b < '0' || b > '9' {
				return 0, false
			}
			i = i*10 + int64(b-'0')
		}
		return i, len(n) > 0
	}
	return 0, false
}

