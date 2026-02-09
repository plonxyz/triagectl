package output

import "github.com/plonxyz/triagectl/internal/models"

// Writer is the interface that all output writers must implement
type Writer interface {
	Write(artifact models.Artifact) error
	WriteMany(artifacts []models.Artifact) error
	Close() error
}
