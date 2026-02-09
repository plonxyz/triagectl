package analysis

import (
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

// PersistenceAnomalyAnalyzer detects suspicious persistence mechanisms
type PersistenceAnomalyAnalyzer struct{}

func (a *PersistenceAnomalyAnalyzer) Name() string { return "persistence_anomaly" }

func (a *PersistenceAnomalyAnalyzer) Analyze(artifacts []models.Artifact) []models.Artifact {
	now := time.Now()

	for i, art := range artifacts {
		score := 0
		var tags []string

		switch art.ArtifactType {
		case "user_launch_agent", "system_launch_agent", "system_launch_daemon":
			score, tags = a.analyzeLaunchAgent(art, now)
		case "user_crontab", "system_cron":
			score, tags = a.analyzeCron(art)
		case "login_item_btm", "login_item_backgrounditems":
			score, tags = a.analyzeLoginItem(art)
		case "library_extension":
			score, tags = a.analyzeExtension(art, now)
		}

		if score > 0 {
			artifacts[i].RiskScore += score
			artifacts[i].Tags = appendUnique(artifacts[i].Tags, tags...)
		}
	}

	return artifacts
}

func (a *PersistenceAnomalyAnalyzer) analyzeLaunchAgent(art models.Artifact, now time.Time) (int, []string) {
	score := 0
	var tags []string

	path := getString(art.Data, "path")
	modTimeStr := getString(art.Data, "mod_time")

	// Modified in last 24h
	if modTimeStr != "" {
		if modTime, err := time.Parse(time.RFC3339, modTimeStr); err == nil {
			if now.Sub(modTime) < 24*time.Hour {
				score += 20
				tags = append(tags, "recently_modified")
			}
		}
	}

	// Binary target in /tmp or user-writable path
	if strings.Contains(path, "/tmp/") || strings.Contains(path, "/var/tmp/") ||
		strings.Contains(path, "/private/tmp/") {
		score += 35
		tags = append(tags, "plist_in_tmp")
	}

	// Non-Apple plist in system directories
	name := getString(art.Data, "name")
	if (art.ArtifactType == "system_launch_agent" || art.ArtifactType == "system_launch_daemon") &&
		!strings.HasPrefix(name, "com.apple.") {
		score += 10
		tags = append(tags, "non_apple_system_plist")
	}

	return score, tags
}

func (a *PersistenceAnomalyAnalyzer) analyzeCron(art models.Artifact) (int, []string) {
	score := 0
	var tags []string

	entry := getString(art.Data, "entry")

	// curl|sh or wget patterns
	entryLower := strings.ToLower(entry)
	if (strings.Contains(entryLower, "curl") || strings.Contains(entryLower, "wget")) &&
		(strings.Contains(entryLower, "| sh") || strings.Contains(entryLower, "|sh") ||
			strings.Contains(entryLower, "| bash") || strings.Contains(entryLower, "|bash")) {
		score += 30
		tags = append(tags, "cron_curl_pipe_sh")
	}

	// Cron pointing to /tmp
	if strings.Contains(entry, "/tmp/") || strings.Contains(entry, "/var/tmp/") {
		score += 20
		tags = append(tags, "cron_tmp_path")
	}

	return score, tags
}

func (a *PersistenceAnomalyAnalyzer) analyzeLoginItem(art models.Artifact) (int, []string) {
	score := 0
	var tags []string

	path := getString(art.Data, "path")
	content := getString(art.Data, "content")

	if strings.Contains(path, "/tmp/") || strings.Contains(content, "/tmp/") {
		score += 25
		tags = append(tags, "login_item_tmp_path")
	}

	return score, tags
}

func (a *PersistenceAnomalyAnalyzer) analyzeExtension(art models.Artifact, now time.Time) (int, []string) {
	score := 0
	var tags []string

	modTimeStr := getString(art.Data, "mod_time")
	if modTimeStr != "" {
		if modTime, err := time.Parse(time.RFC3339, modTimeStr); err == nil {
			if now.Sub(modTime) < 24*time.Hour {
				score += 15
				tags = append(tags, "recently_installed_extension")
			}
		}
	}

	return score, tags
}
