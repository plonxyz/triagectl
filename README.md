# triagectl

A fast, single-binary macOS triage tool for Digital Forensics and Incident Response (DFIR). Collects 26 artifact types, runs automated analysis, and outputs to SQLite, CSV, HTML, and Timesketch-compatible timeline formats.

## Features

- **26 collectors** covering persistence, user activity, network, security posture, and more
- **Automated analysis** -- suspicious process detection, network anomaly scoring, persistence analysis
- **IOC matching** against a custom indicator file (IPs, domains, hashes, paths)
- **Multiple output formats** -- SQLite, CSV, interactive HTML report, Timesketch timeline
- **Concurrent collection** with configurable parallelism and per-collector timeouts
- **Single binary** -- no Python, no agents, no runtime dependencies on the target system
- **Root-aware** -- collects what it can without root, unlocks more with `sudo`

## Quick Start

```bash
# Build
go build -o triagectl ./cmd/triagectl

# Run all collectors
./triagectl

# Run with HTML report + timeline
./triagectl --html --timeline

# Run specific collectors only
./triagectl --collectors system_info,launch_agents,browser_history --html

# Match artifacts against an IOC file
./triagectl --ioc-file indicators.txt --html --timeline
```

## Installation

### From Source

Requires Go 1.22+ and CGO (for SQLite).

```bash
git clone https://github.com/plonxyz/triagectl.git
cd triagectl
go mod download
go build -o triagectl ./cmd/triagectl
```

### Release Build

```bash
go build -ldflags="-s -w" -o triagectl ./cmd/triagectl
```

## Collectors

### System

| Collector | Description | Root |
|---|---|---|
| `system_info` | OS version, hardware, uptime, serial number | No |
| `running_processes` | All processes with CPU, memory, network connections | No |
| `network_connections` | Active TCP/UDP connections | No |
| `network_interfaces` | Interfaces, routing table, DNS configuration | No |
| `user_accounts` | Local user accounts and details | No |

### Persistence

| Collector | Description | Root |
|---|---|---|
| `launch_agents` | LaunchAgents and LaunchDaemons (user and system) | Partial |
| `scheduled_tasks` | Cron jobs, at jobs, periodic tasks | Partial |
| `login_items` | Login items and background task management entries | No |

### User Activity

| Collector | Description | Root |
|---|---|---|
| `browser_history` | Safari and Chrome browsing history | No |
| `recent_files` | Recently accessed files (Downloads, Desktop, Documents) | No |
| `shell_history` | Bash and Zsh command history | No |
| `quarantine_events` | macOS quarantine database (downloaded files) | No |
| `knowledgec` | App usage and screen time from KnowledgeC.db | No |

### Security & Privacy

| Collector | Description | Root |
|---|---|---|
| `tcc_permissions` | TCC privacy permissions database | Partial |
| `ssh_config` | SSH keys, config, known hosts, authorized keys | No |
| `gatekeeper` | Gatekeeper, XProtect, and SIP status | No |
| `firewall` | Application firewall configuration | No |
| `filevault` | FileVault disk encryption status | No |
| `extensions` | System extensions, kernel extensions, third-party extensions | No |
| `environment` | Environment variables (flags suspicious ones like DYLD_INSERT_LIBRARIES) | No |

### Network

| Collector | Description | Root |
|---|---|---|
| `arp_cache` | ARP cache entries for network mapping | No |
| `open_files` | Open network files and connections via lsof | No |

### Logs

| Collector | Description | Root |
|---|---|---|
| `installed_apps` | Installed applications (system and user) | No |
| `system_logs` | Crash reports and diagnostic logs | Partial |
| `unified_logs` | Recent unified log entries (security, network, process, errors) | No |
| `fsevents` | File system events via fs_usage | **Yes** |

## Output Formats

Running `./triagectl` always produces a SQLite database. Additional formats are opt-in:

```
triagectl-output/
  hostname-20260208-143022/
    artifacts.db             # Always: SQLite with indexed columns
    artifacts.csv            # --csv
    report.html              # --html (self-contained, no external deps)
    timeline.csv             # --timeline (Timesketch CSV format)
```

### HTML Report

The `--html` flag generates a self-contained interactive report with:

- Security posture overview (Gatekeeper, SIP, Firewall, FileVault)
- Findings sorted by risk score with expandable raw data
- TCC privacy permissions
- User accounts and SSH configuration
- Running processes with risk scoring
- Persistence mechanisms (LaunchAgents/Daemons, cron, login items)
- Browser history (Safari + Chrome), shell history, downloads
- Network connections and configuration
- Unified logs and crash reports
- Full event timeline
- Per-collector execution statistics

### Timesketch Timeline

The `--timeline` flag produces a CSV file importable directly into [Timesketch](https://timesketch.org/) via the web UI:

```csv
message,datetime,timestamp,timestamp_desc,collector_id,artifact_type,hostname,risk_score,data
"Launch agent: com.example.plist at /Library/LaunchAgents/",2026-02-06T19:01:01Z,1738868461000000,Persistence Modified,launch_agents,system_launch_agent,MacBook-Pro.local,30,"{...}"
```

The first four columns (`message`, `datetime`, `timestamp`, `timestamp_desc`) are the mandatory Timesketch fields. Additional columns are imported as extra attributes.

## Analysis Engine

Every collected artifact passes through the analysis pipeline before output:

| Analyzer | What It Does |
|---|---|
| **Suspicious Process** | Scores processes running from /tmp, known offensive tools (nc, nmap, ...), hidden process names, root processes in user directories |
| **Network Anomaly** | Flags connections to common C2 ports (4444, 5555, 1337, ...), IRC, Tor SOCKS (9050/9150), high connection counts |
| **Persistence Anomaly** | Scores persistence entries: recently modified plists, executables in /tmp, curl-pipe-sh cron jobs |
| **IOC Matcher** | Matches IPs, domains, hashes, and file paths from a user-supplied indicator file (risk score 90) |

Risk scores range from 0-100. Findings with score >= 40 appear in the report's Findings section.

## IOC Matching

Supply a text file with one indicator per line. Lines starting with `#` are comments. Types are auto-detected:

```
# indicators.txt
192.168.1.100
evil-domain.com
44d88612fea8a8f36de82e1278abb02f
/tmp/.hidden/payload
```

```bash
./triagectl --ioc-file indicators.txt --html
```

Matches tag the artifact with the specific IOC (e.g. `ioc_match:domain:evil-domain.com`) and set a risk score of 90.

## CLI Reference

```
Usage: ./triagectl [flags]

Flags:
  --output <dir>              Output directory (default: ./triagectl-output)
  --collectors <ids>          Comma-separated collector IDs (default: all)
  --collector-timeout <sec>   Per-collector timeout (default: 60)
  --concurrency <n>           Max parallel collectors (default: 4)
  --timeout <sec>             Global timeout (default: 300)
  --csv                       Enable CSV output
  --html                      Generate HTML report
  --timeline                  Generate Timesketch timeline
  --ioc-file <path>           Path to IOC indicator file
  --list                      List available collectors and exit
  --version                   Show version and exit
```

## Querying with SQLite

```bash
sqlite3 artifacts.db
```

```sql
-- High-risk findings
SELECT artifact_type, risk_score, tags,
       json_extract(data, '$.name') AS name
FROM artifacts WHERE risk_score >= 40
ORDER BY risk_score DESC;

-- Persistence mechanisms
SELECT artifact_type,
       json_extract(data, '$.name') AS name,
       json_extract(data, '$.path') AS path
FROM artifacts WHERE artifact_type LIKE '%launch%';

-- External network connections
SELECT json_extract(data, '$.remote_addr') AS remote_ip,
       json_extract(data, '$.remote_port') AS remote_port,
       json_extract(data, '$.status') AS status
FROM artifacts
WHERE artifact_type = 'network_connection'
  AND json_extract(data, '$.remote_addr') != '';

-- Browser history
SELECT json_extract(data, '$.url') AS url,
       json_extract(data, '$.title') AS title,
       COALESCE(json_extract(data, '$.visit_time'),
                json_extract(data, '$.last_visit_time')) AS visited
FROM artifacts
WHERE artifact_type IN ('safari_history', 'chrome_history')
ORDER BY visited DESC LIMIT 20;

-- Downloaded files (quarantine)
SELECT json_extract(data, '$.data_url') AS file,
       json_extract(data, '$.origin_url') AS source,
       json_extract(data, '$.agent_name') AS app
FROM artifacts WHERE artifact_type = 'quarantine_event';

-- TCC privacy permissions
SELECT json_extract(data, '$.client') AS app,
       json_extract(data, '$.service') AS permission,
       json_extract(data, '$.auth_value') AS allowed
FROM artifacts WHERE artifact_type = 'tcc_permission';
```

## Extending

Add a new collector by creating a file in `internal/collectors/` implementing the `Collector` interface:

```go
type MyCollector struct{}

func (c *MyCollector) ID() string          { return "my_collector" }
func (c *MyCollector) Name() string        { return "My Collector" }
func (c *MyCollector) Description() string { return "Collects something useful" }
func (c *MyCollector) RequiresRoot() bool  { return false }

func (c *MyCollector) Collect(ctx context.Context) ([]models.Artifact, error) {
    // Collection logic
    return artifacts, nil
}
```

Then add `&MyCollector{}` to the `Registry` slice in `internal/collectors/collector.go`.

## Project Structure

```
cmd/triagectl/main.go          CLI entry point and orchestration
internal/
  collectors/                  26 artifact collectors
  analysis/                    Analysis pipeline (4 analyzers)
  models/artifact.go           Core data model
  output/                      Writers (SQLite, CSV, timeline)
  report/                      HTML report generator + template
  progress/                    Terminal progress display
```

## License

GPL-3.0

## Disclaimer

This tool is intended for authorized forensic investigations and incident response only. Always obtain proper authorization before running on any system.
