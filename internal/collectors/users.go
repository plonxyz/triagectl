package collectors

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type UserAccountsCollector struct{}

func (c *UserAccountsCollector) ID() string          { return "user_accounts" }
func (c *UserAccountsCollector) Name() string        { return "User Accounts" }
func (c *UserAccountsCollector) Description() string { return "Collects local user accounts" }
func (c *UserAccountsCollector) RequiresRoot() bool  { return false }

func (c *UserAccountsCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()

	// Get list of users from /Users directory
	users := c.getLocalUsers()

	var artifacts []models.Artifact

	for _, username := range users {
		userInfo := c.getUserInfo(username)

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "user_account",
			Hostname:     hostname,
			Data:         userInfo,
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts, nil
}

func (c *UserAccountsCollector) getLocalUsers() []string {
	entries, err := os.ReadDir("/Users")
	if err != nil {
		return nil
	}

	var users []string
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") && entry.Name() != "Shared" {
			users = append(users, entry.Name())
		}
	}
	return users
}

func (c *UserAccountsCollector) getUserInfo(username string) map[string]interface{} {
	info := map[string]interface{}{
		"username":  username,
		"home_dir":  "/Users/" + username,
	}

	// Try to get user ID and full name via dscl
	cmd := exec.Command("dscl", ".", "-read", "/Users/"+username)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "UniqueID:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					info["uid"] = parts[1]
				}
			} else if strings.HasPrefix(line, "RealName:") {
				realName := strings.TrimPrefix(line, "RealName:")
				realName = strings.TrimSpace(realName)
				if realName != "" {
					info["real_name"] = realName
				}
			} else if strings.HasPrefix(line, "UserShell:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					info["shell"] = parts[1]
				}
			}
		}
	}

	// Check if user home directory exists
	if _, err := os.Stat("/Users/" + username); err == nil {
		info["home_exists"] = true
	} else {
		info["home_exists"] = false
	}

	return info
}
