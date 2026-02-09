package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type SSHCollector struct{}

func (c *SSHCollector) ID() string          { return "ssh_config" }
func (c *SSHCollector) Name() string        { return "SSH Keys & Configuration" }
func (c *SSHCollector) Description() string { return "Collects SSH keys, configs, and known hosts" }
func (c *SSHCollector) RequiresRoot() bool  { return false }

func (c *SSHCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var artifacts []models.Artifact

	sshDir := filepath.Join(homeDir, ".ssh")

	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return artifacts, nil
	}

	// Collect SSH keys (private and public)
	keyPatterns := []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
	for _, pattern := range keyPatterns {
		// Private key
		privateKey := filepath.Join(sshDir, pattern)
		if info, err := os.Stat(privateKey); err == nil {
			artifact := models.Artifact{
				Timestamp:    time.Now(),
				CollectorID:  c.ID(),
				ArtifactType: "ssh_private_key",
				Hostname:     hostname,
				Data: map[string]interface{}{
					"path":       privateKey,
					"key_type":   pattern,
					"mod_time":   info.ModTime().Format(time.RFC3339),
					"size":       info.Size(),
					"mode":       info.Mode().String(),
				},
				Metadata: models.ArtifactMetadata{
					Success:      true,
					RequiresRoot: false,
					SourcePath:   privateKey,
					CollectedAt:  time.Now().Format(time.RFC3339),
				},
			}
			artifacts = append(artifacts, artifact)
		}

		// Public key
		publicKey := filepath.Join(sshDir, pattern+".pub")
		if info, err := os.Stat(publicKey); err == nil {
			// Read public key content
			content, _ := os.ReadFile(publicKey)

			artifact := models.Artifact{
				Timestamp:    time.Now(),
				CollectorID:  c.ID(),
				ArtifactType: "ssh_public_key",
				Hostname:     hostname,
				Data: map[string]interface{}{
					"path":       publicKey,
					"key_type":   pattern,
					"mod_time":   info.ModTime().Format(time.RFC3339),
					"size":       info.Size(),
					"content":    string(content),
				},
				Metadata: models.ArtifactMetadata{
					Success:      true,
					RequiresRoot: false,
					SourcePath:   publicKey,
					CollectedAt:  time.Now().Format(time.RFC3339),
				},
			}
			artifacts = append(artifacts, artifact)
		}
	}

	// SSH config
	sshConfig := filepath.Join(sshDir, "config")
	if _, err := os.Stat(sshConfig); err == nil {
		content, _ := os.ReadFile(sshConfig)
		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "ssh_config",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"path":    sshConfig,
				"content": string(content),
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				SourcePath:   sshConfig,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}
		artifacts = append(artifacts, artifact)
	}

	// Known hosts
	knownHosts := filepath.Join(sshDir, "known_hosts")
	if _, err := os.Stat(knownHosts); err == nil {
		content, _ := os.ReadFile(knownHosts)
		lines := strings.Split(string(content), "\n")

		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			artifact := models.Artifact{
				Timestamp:    time.Now(),
				CollectorID:  c.ID(),
				ArtifactType: "ssh_known_host",
				Hostname:     hostname,
				Data: map[string]interface{}{
					"line_number": i + 1,
					"entry":       line,
				},
				Metadata: models.ArtifactMetadata{
					Success:      true,
					RequiresRoot: false,
					SourcePath:   knownHosts,
					CollectedAt:  time.Now().Format(time.RFC3339),
				},
			}
			artifacts = append(artifacts, artifact)
		}
	}

	// Authorized keys
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	if _, err := os.Stat(authorizedKeys); err == nil {
		content, _ := os.ReadFile(authorizedKeys)
		lines := strings.Split(string(content), "\n")

		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			artifact := models.Artifact{
				Timestamp:    time.Now(),
				CollectorID:  c.ID(),
				ArtifactType: "ssh_authorized_key",
				Hostname:     hostname,
				Data: map[string]interface{}{
					"line_number": i + 1,
					"key":         line,
				},
				Metadata: models.ArtifactMetadata{
					Success:      true,
					RequiresRoot: false,
					SourcePath:   authorizedKeys,
					CollectedAt:  time.Now().Format(time.RFC3339),
				},
			}
			artifacts = append(artifacts, artifact)
		}
	}

	return artifacts, nil
}
