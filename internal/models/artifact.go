package models

import "time"

// Artifact represents a collected forensic artifact
type Artifact struct {
	Timestamp    time.Time              `json:"timestamp"`
	CollectorID  string                 `json:"collector_id"`
	ArtifactType string                 `json:"artifact_type"`
	Hostname     string                 `json:"hostname"`
	Data         map[string]interface{} `json:"data"`
	Metadata     ArtifactMetadata       `json:"metadata"`
	Severity     string                 `json:"-"`
	RiskScore    int                    `json:"risk_score,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
	EventTime    *time.Time             `json:"event_time,omitempty"`
}

// ArtifactMetadata contains collection metadata
type ArtifactMetadata struct {
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message,omitempty"`
	RequiresRoot bool   `json:"requires_root"`
	SourcePath   string `json:"source_path,omitempty"`
	FileHash     string `json:"file_hash,omitempty"`
	CollectedAt  string `json:"collected_at"`
}

// CollectionResult represents the result of a collector
type CollectionResult struct {
	CollectorID string
	Artifacts   []Artifact
	Error       error
	Duration    time.Duration
	StartedAt   time.Time
}

// SeverityInfo returns a human-readable severity level from risk score
func SeverityFromScore(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	case score >= 20:
		return "low"
	default:
		return "info"
	}
}
