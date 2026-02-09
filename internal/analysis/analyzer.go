package analysis

import "github.com/plonxyz/triagectl/internal/models"

// Analyzer inspects artifacts and enriches them with risk scores, severity, and tags
type Analyzer interface {
	Name() string
	Analyze(artifacts []models.Artifact) []models.Artifact
}

// registry of all analyzers
var analyzers []Analyzer

func init() {
	analyzers = []Analyzer{
		&SuspiciousProcessAnalyzer{},
		&NetworkAnomalyAnalyzer{},
		&PersistenceAnomalyAnalyzer{},
	}
}

// RegisterAnalyzer adds an analyzer to the pipeline (used for IOC matcher)
func RegisterAnalyzer(a Analyzer) {
	analyzers = append(analyzers, a)
}

// RunAll runs all registered analyzers on the artifacts
func RunAll(artifacts []models.Artifact) []models.Artifact {
	for _, a := range analyzers {
		artifacts = a.Analyze(artifacts)
	}
	// Finalize severity from risk scores
	for i := range artifacts {
		if artifacts[i].RiskScore > 0 && artifacts[i].Severity == "" {
			artifacts[i].Severity = models.SeverityFromScore(artifacts[i].RiskScore)
		}
	}
	return artifacts
}
