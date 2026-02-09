package collectors

import (
	"context"
	"os"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/plonxyz/triagectl/internal/models"
)

type NetworkConnectionsCollector struct{}

func (c *NetworkConnectionsCollector) ID() string          { return "network_connections" }
func (c *NetworkConnectionsCollector) Name() string        { return "Network Connections" }
func (c *NetworkConnectionsCollector) Description() string { return "Collects active network connections" }
func (c *NetworkConnectionsCollector) RequiresRoot() bool  { return false }

func (c *NetworkConnectionsCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()

	connections, err := net.Connections("all")
	if err != nil {
		return nil, err
	}

	var artifacts []models.Artifact

	for _, conn := range connections {
		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "network_connection",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"fd":          conn.Fd,
				"family":      conn.Family,
				"type":        conn.Type,
				"local_addr":  conn.Laddr.IP,
				"local_port":  conn.Laddr.Port,
				"remote_addr": conn.Raddr.IP,
				"remote_port": conn.Raddr.Port,
				"status":      conn.Status,
				"pid":         conn.Pid,
			},
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
