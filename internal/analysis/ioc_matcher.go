package analysis

import (
	"bufio"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/plonxyz/triagectl/internal/models"
)

// IOCMatcher matches artifacts against a list of Indicators of Compromise
type IOCMatcher struct {
	ips     map[string]bool
	domains map[string]bool
	hashes  map[string]bool
	paths   map[string]bool
}

func (m *IOCMatcher) Name() string { return "ioc_matcher" }

// NewIOCMatcher loads IOCs from a file (one per line, auto-detects type)
func NewIOCMatcher(filePath string) (*IOCMatcher, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := &IOCMatcher{
		ips:     make(map[string]bool),
		domains: make(map[string]bool),
		hashes:  make(map[string]bool),
		paths:   make(map[string]bool),
	}

	hashRegex := regexp.MustCompile(`^[0-9a-fA-F]{32,128}$`)
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$`)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case net.ParseIP(line) != nil:
			m.ips[line] = true
		case hashRegex.MatchString(line):
			m.hashes[strings.ToLower(line)] = true
		case strings.HasPrefix(line, "/"):
			m.paths[line] = true
		case domainRegex.MatchString(line):
			m.domains[strings.ToLower(line)] = true
		default:
			// Try as domain anyway
			m.domains[strings.ToLower(line)] = true
		}
	}

	return m, scanner.Err()
}

func (m *IOCMatcher) Analyze(artifacts []models.Artifact) []models.Artifact {
	for i, art := range artifacts {
		matched := false
		var tags []string

		// Check all string values in Data for matches
		for _, v := range art.Data {
			s, ok := v.(string)
			if !ok {
				continue
			}

			// IP match
			for ip := range m.ips {
				if strings.Contains(s, ip) {
					matched = true
					tags = append(tags, "ioc_match:ip:"+ip)
				}
			}

			// Domain match
			sLower := strings.ToLower(s)
			for domain := range m.domains {
				if strings.Contains(sLower, domain) {
					matched = true
					tags = append(tags, "ioc_match:domain:"+domain)
				}
			}

			// Hash match
			for hash := range m.hashes {
				if strings.Contains(sLower, hash) {
					matched = true
					tags = append(tags, "ioc_match:hash:"+hash)
				}
			}

			// Path match
			for path := range m.paths {
				if strings.Contains(s, path) {
					matched = true
					tags = append(tags, "ioc_match:path:"+path)
				}
			}
		}

		if matched {
			artifacts[i].RiskScore = 90
			artifacts[i].Tags = appendUnique(artifacts[i].Tags, "ioc_match")
			artifacts[i].Tags = appendUnique(artifacts[i].Tags, tags...)
		}
	}

	return artifacts
}
