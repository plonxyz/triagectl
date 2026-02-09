package output

import (
	"encoding/csv"
	"encoding/json"
	"os"

	"github.com/plonxyz/triagectl/internal/models"
)

// CSVWriter writes artifacts to a CSV file
type CSVWriter struct {
	file   *os.File
	writer *csv.Writer
}

// compile-time interface check
var _ Writer = (*CSVWriter)(nil)

// NewCSVWriter creates a new CSV writer
func NewCSVWriter(outputPath string) (*CSVWriter, error) {
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, err
	}

	w := csv.NewWriter(file)

	// Write header
	header := []string{
		"timestamp", "collector_id", "artifact_type", "hostname",
		"risk_score", "event_time", "data_json",
	}
	if err := w.Write(header); err != nil {
		file.Close()
		return nil, err
	}

	return &CSVWriter{
		file:   file,
		writer: w,
	}, nil
}

// Write writes an artifact to the CSV file
func (cw *CSVWriter) Write(artifact models.Artifact) error {
	dataJSON, err := json.Marshal(artifact.Data)
	if err != nil {
		return err
	}

	var eventTime string
	if artifact.EventTime != nil {
		eventTime = artifact.EventTime.Format("2006-01-02T15:04:05.000Z")
	}

	riskScore := ""
	if artifact.RiskScore > 0 {
		riskScore = json.Number(itoa(artifact.RiskScore)).String()
	}

	record := []string{
		artifact.Timestamp.Format("2006-01-02T15:04:05.000Z"),
		artifact.CollectorID,
		artifact.ArtifactType,
		artifact.Hostname,
		riskScore,
		eventTime,
		string(dataJSON),
	}

	return cw.writer.Write(record)
}

// WriteMany writes multiple artifacts to the CSV file
func (cw *CSVWriter) WriteMany(artifacts []models.Artifact) error {
	for _, artifact := range artifacts {
		if err := cw.Write(artifact); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes and closes the CSV writer
func (cw *CSVWriter) Close() error {
	cw.writer.Flush()
	if err := cw.writer.Error(); err != nil {
		cw.file.Close()
		return err
	}
	return cw.file.Close()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
