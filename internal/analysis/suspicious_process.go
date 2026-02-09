package analysis

import (
	"fmt"
	"strings"

	"github.com/plonxyz/triagectl/internal/models"
)

// SuspiciousProcessAnalyzer detects suspicious running processes
type SuspiciousProcessAnalyzer struct{}

func (a *SuspiciousProcessAnalyzer) Name() string { return "suspicious_process" }

var suspiciousNames = map[string]bool{
	"nc": true, "ncat": true, "socat": true, "base64": true,
	"osascript": true, "nmap": true, "tcpdump": true,
	"python": true, "perl": true, "ruby": true,
	"tor": true, "obfs4proxy": true, "snowflake-client": true,
}

func (a *SuspiciousProcessAnalyzer) Analyze(artifacts []models.Artifact) []models.Artifact {
	for i, art := range artifacts {
		if art.ArtifactType != "running_process" {
			continue
		}

		score := 0
		var tags []string

		exe := getString(art.Data, "exe")
		name := getString(art.Data, "name")
		username := getString(art.Data, "username")
		cwd := getString(art.Data, "cwd")

		// Exe in /tmp or /var/tmp
		if strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/var/tmp/") ||
			strings.HasPrefix(exe, "/private/tmp/") || strings.HasPrefix(exe, "/private/var/tmp/") {
			score += 30
			tags = append(tags, "exe_in_tmp")
		}

		// Known suspicious process names
		baseName := name
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			baseName = name[idx+1:]
		}
		if suspiciousNames[strings.ToLower(baseName)] {
			score += 20
			tags = append(tags, fmt.Sprintf("suspicious_name:%s", baseName))
		}

		// No exe path
		if exe == "" && name != "" {
			score += 15
			tags = append(tags, "no_exe_path")
		}

		// Root process in user directories
		if username == "root" && (strings.HasPrefix(cwd, "/Users/") || strings.HasPrefix(exe, "/Users/")) {
			score += 25
			tags = append(tags, "root_in_user_dir")
		}

		// Hidden process name (starts with .)
		if strings.HasPrefix(baseName, ".") {
			score += 20
			tags = append(tags, "hidden_process")
		}

		if score > 0 {
			artifacts[i].RiskScore += score
			artifacts[i].Tags = appendUnique(artifacts[i].Tags, tags...)
		}
	}

	return artifacts
}

func getString(d map[string]interface{}, key string) string {
	if v, ok := d[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func appendUnique(existing []string, items ...string) []string {
	seen := make(map[string]bool)
	for _, s := range existing {
		seen[s] = true
	}
	for _, item := range items {
		if !seen[item] {
			existing = append(existing, item)
			seen[item] = true
		}
	}
	return existing
}
