package collectors

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

type NetworkInterfacesCollector struct{}

func (c *NetworkInterfacesCollector) ID() string          { return "network_interfaces" }
func (c *NetworkInterfacesCollector) Name() string        { return "Network Interfaces" }
func (c *NetworkInterfacesCollector) Description() string { return "Collects network interface details" }
func (c *NetworkInterfacesCollector) RequiresRoot() bool  { return false }

func (c *NetworkInterfacesCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
	hostname, _ := os.Hostname()
	var artifacts []models.Artifact

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		var addresses []string
		for _, addr := range addrs {
			addresses = append(addresses, addr.String())
		}

		data := map[string]interface{}{
			"name":       iface.Name,
			"mtu":        iface.MTU,
			"mac":        iface.HardwareAddr.String(),
			"flags":      iface.Flags.String(),
			"addresses":  addresses,
		}

		// Get additional details from ifconfig
		ifconfigData := c.getIfconfigData(iface.Name)
		for k, v := range ifconfigData {
			data[k] = v
		}

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "network_interface",
			Hostname:     hostname,
			Data:         data,
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
	}

	// Get routing table
	routingTable := c.getRoutingTable(hostname)
	artifacts = append(artifacts, routingTable...)

	// Get DNS configuration
	dnsConfig := c.getDNSConfig(hostname)
	artifacts = append(artifacts, dnsConfig...)

	return artifacts, nil
}

func (c *NetworkInterfacesCollector) getIfconfigData(ifaceName string) map[string]interface{} {
	data := make(map[string]interface{})

	cmd := exec.Command("ifconfig", ifaceName)
	output, err := cmd.Output()
	if err != nil {
		return data
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "status:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				data["status"] = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "media:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				data["media"] = strings.TrimSpace(parts[1])
			}
		}
	}

	return data
}

func (c *NetworkInterfacesCollector) getRoutingTable(hostname string) []models.Artifact {
	var artifacts []models.Artifact

	cmd := exec.Command("netstat", "-nr")
	output, err := cmd.Output()
	if err != nil {
		return artifacts
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Routing") || strings.HasPrefix(line, "Destination") || strings.HasPrefix(line, "Internet") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "routing_table_entry",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"destination": fields[0],
				"gateway":     fields[1],
				"flags":       fields[2],
				"interface":   fields[len(fields)-1],
				"raw_line":    line,
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}

		artifacts = append(artifacts, artifact)
	}

	return artifacts
}

func (c *NetworkInterfacesCollector) getDNSConfig(hostname string) []models.Artifact {
	var artifacts []models.Artifact

	// Read /etc/resolv.conf
	content, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			artifact := models.Artifact{
				Timestamp:    time.Now(),
				CollectorID:  c.ID(),
				ArtifactType: "dns_config",
				Hostname:     hostname,
				Data: map[string]interface{}{
					"entry":  line,
					"source": "/etc/resolv.conf",
				},
				Metadata: models.ArtifactMetadata{
					Success:      true,
					RequiresRoot: false,
					SourcePath:   "/etc/resolv.conf",
					CollectedAt:  time.Now().Format(time.RFC3339),
				},
			}

			artifacts = append(artifacts, artifact)
		}
	}

	// Get scutil DNS info
	cmd := exec.Command("scutil", "--dns")
	output, err := cmd.Output()
	if err == nil {
		artifact := models.Artifact{
			Timestamp:    time.Now(),
			CollectorID:  c.ID(),
			ArtifactType: "dns_config_scutil",
			Hostname:     hostname,
			Data: map[string]interface{}{
				"output": string(output),
				"source": "scutil --dns",
			},
			Metadata: models.ArtifactMetadata{
				Success:      true,
				RequiresRoot: false,
				CollectedAt:  time.Now().Format(time.RFC3339),
			},
		}
		artifacts = append(artifacts, artifact)
	}

	return artifacts
}
