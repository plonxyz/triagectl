package collectors

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type RecentFilesCollector struct{}

func (c *RecentFilesCollector) ID() string          { return "recent_files" }
func (c *RecentFilesCollector) Name() string        { return "Recent Files" }
func (c *RecentFilesCollector) Description() string { return "Collects recently accessed files from user directories" }
func (c *RecentFilesCollector) RequiresRoot() bool  { return false }

func (c *RecentFilesCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var artifacts []models.Artifact

	dirs := []struct {
		path     string
		fileType string
	}{
		{filepath.Join(homeDir, "Downloads"), "download"},
		{filepath.Join(homeDir, "Desktop"), "desktop"},
		{filepath.Join(homeDir, "Documents"), "document"},
	}

	for _, dir := range dirs {
		if ctx.Err() != nil {
			break
		}
		dirArtifacts := c.collectRecentFiles(ctx, dir.path, dir.fileType, hostname, 500)
		artifacts = append(artifacts, dirArtifacts...)
	}

	return artifacts, nil
}

type fileEntry struct {
	path    string
	info    os.FileInfo
}

func (c *RecentFilesCollector) collectRecentFiles(ctx context.Context, dirPath, fileType, hostname string, limit int) []models.Artifact {
	var artifacts []models.Artifact
	var files []fileEntry

	// Cap the number of files we consider to avoid slow sorting on huge trees.
	const maxScan = 10000

	_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			return nil
		}
		if len(files) >= maxScan {
			return filepath.SkipAll
		}
		if !info.IsDir() && info.Mode().IsRegular() {
			files = append(files, fileEntry{path: path, info: info})
		}
		return nil
	})

	sort.Slice(files, func(i, j int) bool {
		return files[i].info.ModTime().After(files[j].info.ModTime())
	})

	count := 0
	for _, f := range files {
		if count >= limit {
			break
		}

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "recent_file",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"path":      f.path,
				"name":      f.info.Name(),
				"size":      f.info.Size(),
				"mod_time":  f.info.ModTime().Format(time.RFC3339),
				"file_type": fileType,
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				SourcePath:   f.path,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
		count++
	}

	return artifacts
}
