package analysis

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/plonxyz/triagectl/internal/models"
)

// NetworkAnomalyAnalyzer detects suspicious network connections
type NetworkAnomalyAnalyzer struct{}

func (a *NetworkAnomalyAnalyzer) Name() string { return "network_anomaly" }

var c2Ports = map[int]bool{
	4444: true, 5555: true, 1337: true, 31337: true,
	8443: true, 9999: true, 1234: true,
}

var ircPorts = map[int]bool{
	6667: true, 6668: true, 6669: true, 6697: true,
}

var torPorts = map[int]bool{
	9050: true, 9150: true,
}

func (a *NetworkAnomalyAnalyzer) Analyze(artifacts []models.Artifact) []models.Artifact {
	// Count connections per PID for high-count detection
	pidConnCount := make(map[string]int)
	for _, art := range artifacts {
		if art.ArtifactType == "network_connection" || art.ArtifactType == "open_network_file" {
			pid := getString(art.Data, "pid")
			if pid != "" {
				pidConnCount[pid]++
			}
		}
	}

	for i, art := range artifacts {
		if art.ArtifactType != "network_connection" && art.ArtifactType != "open_network_file" {
			continue
		}

		score := 0
		var tags []string

		remotePort := getPort(art.Data, "remote_port")
		if remotePort == 0 {
			// Try extracting from remote_addr for open_files
			if addr := getString(art.Data, "remote_addr"); addr != "" {
				if idx := strings.LastIndex(addr, ":"); idx >= 0 {
					remotePort, _ = strconv.Atoi(addr[idx+1:])
				}
			}
		}

		remoteAddr := getString(art.Data, "remote_addr")
		isExternal := remoteAddr != "" &&
			!strings.HasPrefix(remoteAddr, "127.") &&
			!strings.HasPrefix(remoteAddr, "::1") &&
			remoteAddr != "0.0.0.0" &&
			remoteAddr != "*"

		// Common C2 ports
		if remotePort > 0 && c2Ports[remotePort] && isExternal {
			score += 30
			tags = append(tags, fmt.Sprintf("c2_port:%d", remotePort))
		}

		// IRC ports to external IPs
		if remotePort > 0 && ircPorts[remotePort] && isExternal {
			score += 20
			tags = append(tags, "irc_connection")
		}

		// Tor ports (check both remote and local — Tor listens locally on SOCKS port)
		localPort := getPort(art.Data, "local_port")
		if (remotePort > 0 && torPorts[remotePort]) || (localPort > 0 && torPorts[localPort]) {
			score += 20
			tags = append(tags, "tor_connection")
		}

		// High connection count from single PID
		pid := getString(art.Data, "pid")
		if pid != "" && pidConnCount[pid] > 50 {
			score += 10
			tags = append(tags, "high_conn_count")
		}

		if score > 0 {
			artifacts[i].RiskScore += score
			artifacts[i].Tags = appendUnique(artifacts[i].Tags, tags...)
		}
	}

	return artifacts
}

func getPort(d map[string]interface{}, key string) int {
	v := getString(d, key)
	if v == "" {
		return 0
	}
	p, _ := strconv.Atoi(v)
	return p
}
