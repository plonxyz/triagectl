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

type BrowserHistoryCollector struct{}

func (c *BrowserHistoryCollector) ID() string          { return "browser_history" }
func (c *BrowserHistoryCollector) Name() string        { return "Browser History" }
func (c *BrowserHistoryCollector) Description() string { return "Collects browser history from Safari and Chrome" }
func (c *BrowserHistoryCollector) RequiresRoot() bool  { return false }

func (c *BrowserHistoryCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var artifacts []models.Artifact

	// Safari History
	safariHistory := filepath.Join(homeDir, "Library/Safari/History.db")
	safariArtifacts := c.collectSafariHistory(safariHistory, hostname)
	artifacts = append(artifacts, safariArtifacts...)

	// Chrome History
	chromeHistory := filepath.Join(homeDir, "Library/Application Support/Google/Chrome/Default/History")
	chromeArtifacts := c.collectChromeHistory(chromeHistory, hostname)
	artifacts = append(artifacts, chromeArtifacts...)

	return artifacts, nil
}

func (c *BrowserHistoryCollector) collectSafariHistory(dbPath string, hostname string) []models.Artifact {
	var artifacts []models.Artifact

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return artifacts
	}

	// Copy database to avoid lock issues
	tmpDB := filepath.Join(os.TempDir(), "safari_history_copy.db")
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

	rows, err := db.Query(`
		SELECT url, title, visit_time, visit_count
		FROM history_visits
		JOIN history_items ON history_visits.history_item = history_items.id
		ORDER BY visit_time DESC
	`)
	if err != nil {
		return artifacts
	}
	defer rows.Close()

	for rows.Next() {
		var url, title string
		var visitTime float64
		var visitCount int

		if err := rows.Scan(&url, &title, &visitTime, &visitCount); err != nil {
			continue
		}

		// Safari stores time as Mac absolute time (seconds since 2001-01-01)
		macEpoch := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
		visitDateTime := macEpoch.Add(time.Duration(visitTime) * time.Second)

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "safari_history",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"url":         url,
				"title":       title,
				"visit_time":  visitDateTime.Format(time.RFC3339),
				"visit_count": visitCount,
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				SourcePath:   dbPath,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts
}

func (c *BrowserHistoryCollector) collectChromeHistory(dbPath string, hostname string) []models.Artifact {
	var artifacts []models.Artifact

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return artifacts
	}

	// Copy database to avoid lock issues
	tmpDB := filepath.Join(os.TempDir(), "chrome_history_copy.db")
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

	rows, err := db.Query(`
		SELECT url, title, visit_count, last_visit_time
		FROM urls
		ORDER BY last_visit_time DESC
	`)
	if err != nil {
		return artifacts
	}
	defer rows.Close()

	for rows.Next() {
		var url, title string
		var visitCount int
		var lastVisitTime int64

		if err := rows.Scan(&url, &title, &visitCount, &lastVisitTime); err != nil {
			continue
		}

		// Chrome stores time as microseconds since 1601-01-01
		// Convert via Unix epoch to avoid int64 overflow in time.Duration
		const chromeToUnixDelta int64 = 11644473600 // seconds between 1601-01-01 and 1970-01-01
		unixSec := lastVisitTime/1000000 - chromeToUnixDelta
		visitDateTime := time.Unix(unixSec, (lastVisitTime%1000000)*1000)

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "chrome_history",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"url":              url,
				"title":            title,
				"visit_count":      visitCount,
				"last_visit_time":  visitDateTime.Format(time.RFC3339),
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				SourcePath:   dbPath,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts
}
