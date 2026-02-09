package collectors

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/plonxyz/triagectl/internal/models"
)

type TCCCollector struct{}

func (c *TCCCollector) ID() string          { return "tcc_permissions" }
func (c *TCCCollector) Name() string        { return "TCC Privacy Permissions" }
func (c *TCCCollector) Description() string { return "Collects Transparency, Consent, and Control database" }
func (c *TCCCollector) RequiresRoot() bool  { return false }

func (c *TCCCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var artifacts []models.Artifact

	// User TCC database
	userTCC := filepath.Join(homeDir, "Library/Application Support/com.apple.TCC/TCC.db")
	userArtifacts := c.collectTCCDatabase(userTCC, "user", hostname)
	artifacts = append(artifacts, userArtifacts...)

	// System TCC database (requires root)
	systemTCC := "/Library/Application Support/com.apple.TCC/TCC.db"
	systemArtifacts := c.collectTCCDatabase(systemTCC, "system", hostname)
	artifacts = append(artifacts, systemArtifacts...)

	return artifacts, nil
}

func (c *TCCCollector) collectTCCDatabase(dbPath, dbType, hostname string) []models.Artifact {
	var artifacts []models.Artifact

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return artifacts
	}

	// Copy database to avoid lock issues
	tmpDB := filepath.Join(os.TempDir(), fmt.Sprintf("tcc_%s_copy.db", dbType))
	defer os.Remove(tmpDB)

	input, err := os.ReadFile(dbPath)
	if err != nil {
		return artifacts
	}

	if err := os.WriteFile(tmpDB, input, 0600); err != nil {
		return artifacts
	}

	db, err := sql.Open("sqlite3", tmpDB)
	if err != nil {
		return artifacts
	}
	defer db.Close()

	// TCC database schema varies by macOS version, try both queries
	queries := []string{
		`SELECT service, client, client_type, auth_value, auth_reason, indirect_object_identifier, last_modified
		 FROM access`,
		`SELECT service, client, client_type, allowed, prompt_count, last_modified
		 FROM access`,
	}

	var rows *sql.Rows
	for _, query := range queries {
		rows, err = db.Query(query)
		if err == nil {
			break
		}
	}

	if err != nil || rows == nil {
		return artifacts
	}
	defer rows.Close()

	columns, _ := rows.Columns()

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		data := map[string]interface{}{
			"database_type": dbType,
		}

		for i, col := range columns {
			val := values[i]
			switch v := val.(type) {
			case []byte:
				data[col] = string(v)
			case int64:
				if col == "last_modified" {
					// TCC stores Unix timestamp
					data[col] = time.Unix(v, 0).Format(time.RFC3339)
				} else {
					data[col] = v
				}
			default:
				data[col] = v
			}
		}

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "tcc_permission",
			Hostname:     hostname,
			Data:         data,
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: dbType == "system",
				SourcePath:   dbPath,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts
}
