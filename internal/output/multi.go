package output

import "github.com/plonxyz/triagectl/internal/models"

// MultiWriter fans out writes to all active writers
type MultiWriter struct {
	writers []Writer
}

// NewMultiWriter creates a MultiWriter from the given writers
func NewMultiWriter(writers ...Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

// Write writes an artifact to all writers
func (mw *MultiWriter) Write(artifact models.Artifact) error {
	for _, w := range mw.writers {
		if err := w.Write(artifact); err != nil {
			return err
		}
	}
	return nil
}

// WriteMany writes multiple artifacts to all writers
func (mw *MultiWriter) WriteMany(artifacts []models.Artifact) error {
	for _, w := range mw.writers {
		if err := w.WriteMany(artifacts); err != nil {
			return err
		}
	}
	return nil
}

// Close closes all writers
func (mw *MultiWriter) Close() error {
	var firstErr error
	for _, w := range mw.writers {
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// compile-time interface check
var _ Writer = (*MultiWriter)(nil)
