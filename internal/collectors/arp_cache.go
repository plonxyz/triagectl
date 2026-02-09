package collectors

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type ARPCacheCollector struct{}

func (c *ARPCacheCollector) ID() string          { return "arp_cache" }
func (c *ARPCacheCollector) Name() string        { return "ARP Cache" }
func (c *ARPCacheCollector) Description() string { return "Collects ARP cache entries for network mapping" }
func (c *ARPCacheCollector) RequiresRoot() bool  { return false }

func (c *ARPCacheCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	var artifacts []models.Artifact

	out, err := exec.CommandContext(ctx, "arp", "-a").CombinedOutput()
	if err != nil {
		return nil, err
	}

	// Parse arp -a output: hostname (IP) at MAC on interface [ifscope ...]
	arpRegex := regexp.MustCompile(`^\?\s*\(([^)]+)\)\s+at\s+(\S+)\s+on\s+(\S+)(.*)$`)
	namedRegex := regexp.MustCompile(`^(\S+)\s+\(([^)]+)\)\s+at\s+(\S+)\s+on\s+(\S+)(.*)$`)

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		data := map[string]interface{}{
			"raw_line": line,
		}

		if m := namedRegex.FindStringSubmatch(line); m != nil {
			data["hostname"] = m[1]
			data["ip"] = m[2]
			data["mac"] = m[3]
			data["interface"] = m[4]
			if m[5] != "" {
				data["flags"] = strings.TrimSpace(m[5])
			}
		} else if m := arpRegex.FindStringSubmatch(line); m != nil {
			data["ip"] = m[1]
			data["mac"] = m[2]
			data["interface"] = m[3]
			if m[4] != "" {
				data["flags"] = strings.TrimSpace(m[4])
			}
		}

		artifacts = append(artifacts, models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "arp_entry",
			Hostname:     hostname,
			Data:         data,
			Metadata: models.ArtifactMetadata{
				Success:     true,
				CollectedAt: time.Now().Format(time.RFC3339),
			},
		})
	}

	return artifacts, nil
}
