package output

import (
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"github.com/plonxyz/triagectl/internal/models"
)

// SQLiteWriter writes artifacts to a SQLite database
type SQLiteWriter struct {
	db *sql.DB
}

// compile-time interface check
var _ Writer = (*SQLiteWriter)(nil)

// NewSQLiteWriter creates a new SQLite writer
func NewSQLiteWriter(outputPath string) (*SQLiteWriter, error) {
	db, err := sql.Open("sqlite3", outputPath)
	if err != nil {
		return nil, err
	}

	writer := &SQLiteWriter{db: db}

	if err := writer.createSchema(); err != nil {
		db.Close()
		return nil, err
	}

	return writer, nil
}

// createSchema creates the database schema
func (w *SQLiteWriter) createSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS artifacts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		collector_id TEXT NOT NULL,
		artifact_type TEXT NOT NULL,
		hostname TEXT NOT NULL,
		data TEXT NOT NULL,
		metadata TEXT NOT NULL,
		success BOOLEAN NOT NULL,
		error_message TEXT,
		requires_root BOOLEAN NOT NULL,
		source_path TEXT,
		collected_at TEXT NOT NULL,
		risk_score INTEGER DEFAULT 0,
		tags TEXT DEFAULT '[]',
		event_time TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_collector_id ON artifacts(collector_id);
	CREATE INDEX IF NOT EXISTS idx_artifact_type ON artifacts(artifact_type);
	CREATE INDEX IF NOT EXISTS idx_hostname ON artifacts(hostname);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON artifacts(timestamp);
	CREATE INDEX IF NOT EXISTS idx_event_time ON artifacts(event_time);
	`

	_, err := w.db.Exec(schema)
	return err
}

// Write writes an artifact to the SQLite database
func (w *SQLiteWriter) Write(artifact models.Artifact) error {
	dataJSON, err := json.Marshal(artifact.Data)
	if err != nil {
		return err
	}

	metadataJSON, err := json.Marshal(artifact.Metadata)
	if err != nil {
		return err
	}

	tagsJSON, err := json.Marshal(artifact.Tags)
	if err != nil {
		return err
	}

	var eventTimeStr string
	if artifact.EventTime != nil {
		eventTimeStr = artifact.EventTime.Format("2006-01-02T15:04:05.000Z")
	}

	query := `
		INSERT INTO artifacts (
			timestamp, collector_id, artifact_type, hostname, data, metadata,
			success, error_message, requires_root, source_path, collected_at,
			risk_score, tags, event_time
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = w.db.Exec(
		query,
		artifact.Timestamp.Format("2006-01-02T15:04:05.000Z"),
		artifact.CollectorID,
		artifact.ArtifactType,
		artifact.Hostname,
		string(dataJSON),
		string(metadataJSON),
		artifact.Metadata.Success,
		artifact.Metadata.ErrorMessage,
		artifact.Metadata.RequiresRoot,
		artifact.Metadata.SourcePath,
		artifact.Metadata.CollectedAt,
		artifact.RiskScore,
		string(tagsJSON),
		eventTimeStr,
	)

	return err
}

// WriteMany writes multiple artifacts using transaction
func (w *SQLiteWriter) WriteMany(artifacts []models.Artifact) error {
	tx, err := w.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
		INSERT INTO artifacts (
			timestamp, collector_id, artifact_type, hostname, data, metadata,
			success, error_message, requires_root, source_path, collected_at,
			risk_score, tags, event_time
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, artifact := range artifacts {
		dataJSON, err := json.Marshal(artifact.Data)
		if err != nil {
			tx.Rollback()
			return err
		}

		metadataJSON, err := json.Marshal(artifact.Metadata)
		if err != nil {
			tx.Rollback()
			return err
		}

		tagsJSON, err := json.Marshal(artifact.Tags)
		if err != nil {
			tx.Rollback()
			return err
		}

		var eventTimeStr string
		if artifact.EventTime != nil {
			eventTimeStr = artifact.EventTime.Format("2006-01-02T15:04:05.000Z")
		}

		_, err = stmt.Exec(
			artifact.Timestamp.Format("2006-01-02T15:04:05.000Z"),
			artifact.CollectorID,
			artifact.ArtifactType,
			artifact.Hostname,
			string(dataJSON),
			string(metadataJSON),
			artifact.Metadata.Success,
			artifact.Metadata.ErrorMessage,
			artifact.Metadata.RequiresRoot,
			artifact.Metadata.SourcePath,
			artifact.Metadata.CollectedAt,
			artifact.RiskScore,
			string(tagsJSON),
			eventTimeStr,
		)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

// UpdateArtifact updates risk_score and tags for an artifact by ID
func (w *SQLiteWriter) UpdateArtifact(id int64, riskScore int, tags []string) error {
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return err
	}
	_, err = w.db.Exec(
		`UPDATE artifacts SET risk_score = ?, tags = ? WHERE id = ?`,
		riskScore, string(tagsJSON), id,
	)
	return err
}

// Close closes the SQLite writer
func (w *SQLiteWriter) Close() error {
	return w.db.Close()
}

// DB returns the underlying database for direct queries
func (w *SQLiteWriter) DB() *sql.DB {
	return w.db
}

// Query executes a SQL query and returns results
func (w *SQLiteWriter) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return w.db.Query(query, args...)
}

// GetStats returns collection statistics
func (w *SQLiteWriter) GetStats() (map[string]int, error) {
	stats := make(map[string]int)

	rows, err := w.db.Query(`
		SELECT collector_id, COUNT(*) as count
		FROM artifacts
		GROUP BY collector_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var collectorID string
		var count int

		if err := rows.Scan(&collectorID, &count); err != nil {
			return nil, err
		}

		stats[collectorID] = count
	}

	// Total count
	var total int
	err = w.db.QueryRow("SELECT COUNT(*) FROM artifacts").Scan(&total)
	if err != nil {
		return nil, err
	}
	stats["total"] = total

	return stats, nil
}

// PrintStats prints collection statistics
func (w *SQLiteWriter) PrintStats() error {
	stats, err := w.GetStats()
	if err != nil {
		return err
	}

	fmt.Println("\nCollection Statistics:")
	fmt.Println("=====================")

	total := stats["total"]
	delete(stats, "total")

	for collector, count := range stats {
		fmt.Printf("  %-25s: %d artifacts\n", collector, count)
	}

	fmt.Println("---------------------")
	fmt.Printf("  %-25s: %d artifacts\n", "TOTAL", total)

	return nil
}
