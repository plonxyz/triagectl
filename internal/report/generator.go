package report

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/plonxyz/triagectl/internal/models"
)

//go:embed report_template.html
var templateFS embed.FS

// CollectorStat holds per-collector statistics
type CollectorStat struct {
	ID       string
	Count    int
	Duration string
	Success  bool
}

// SecurityPostureItem represents a security setting status
type SecurityPostureItem struct {
	Name    string
	Enabled bool
}

// FindingRow represents a row in the findings table
type FindingRow struct {
	ArtifactType string
	CollectorID  string
	Summary      string
	RiskScore    int
	Tags         []string
	DataJSON     string
}

// TimelineRow is a simplified timeline entry for the template
type TimelineRow struct {
	EventTime    string
	ArtifactType string
	CollectorID  string
	Summary      string
}

// PersistenceRow represents a persistence mechanism
type PersistenceRow struct {
	ArtifactType string
	Name         string
	Path         string
	Program      string
	RiskScore    int
}

// NetworkRow is a network artifact for the report
type NetworkRow struct {
	ArtifactType string
	Summary      string
	RiskScore    int
}

// ProcessRow represents a process entry
type ProcessRow struct {
	PID       string
	PPID      string
	Name      string
	User      string
	Exe       string
	CPU       string
	Mem       string
	RiskScore int
}

// UserActivityRow represents user activity
type UserActivityRow struct {
	ArtifactType string
	Summary      string
	EventTime    string
}

// UserAccountRow represents a local user account
type UserAccountRow struct {
	Username string
	RealName string
	UID      string
	Home     string
	Shell    string
}

// TCCRow represents a TCC privacy permission entry
type TCCRow struct {
	Service  string
	Client   string
	AuthValue string
	DBType   string
}

// SSHRow represents an SSH artifact
type SSHRow struct {
	ArtifactType string
	Path         string
	Detail       string
	RiskScore    int
}

// InstalledAppRow represents an installed application
type InstalledAppRow struct {
	Name    string
	Path    string
	ModTime string
	Source  string
}

// LogRow represents a log entry
type LogRow struct {
	ArtifactType string
	Summary      string
	Time         string
}

// EnvironmentRow represents an environment variable
type EnvironmentRow struct {
	Key       string
	Value     string
	Reason    string
	RiskScore int
}

// ReportData is the full data model passed to the HTML template
type ReportData struct {
	// System profile
	Hostname       string
	OS             string
	OSVersion      string
	BuildVersion   string
	KernelVersion  string
	SerialNumber   string
	Architecture   string
	NumCPUs        string
	Uptime         string
	GeneratedAt    string
	TotalArtifacts int
	CollectorsRun  int
	Duration       string

	// Findings count
	FindingsCount int

	// Sections (FOR518-aligned)
	SecurityPosture []SecurityPostureItem
	TCCPermissions  []TCCRow
	Environment     []EnvironmentRow
	Findings        []FindingRow
	UserAccounts    []UserAccountRow
	SSHArtifacts    []SSHRow
	Processes       []ProcessRow
	InstalledApps   []InstalledAppRow
	Persistence     []PersistenceRow
	BrowserHistory  []UserActivityRow
	ShellHistory    []UserActivityRow
	Downloads       []UserActivityRow
	AppUsage        []UserActivityRow
	Network         []NetworkRow
	Logs            []LogRow
	AllTimeline     []TimelineRow
	Timeline        []TimelineRow
	RemainingTimeline []TimelineRow
	CollectorStats  []CollectorStat
}

// GenerateHTMLReport creates an HTML report from artifacts and results
func GenerateHTMLReport(
	outputPath string,
	artifacts []models.Artifact,
	results []models.CollectionResult,
	duration time.Duration,
) error {
	tmplData, err := templateFS.ReadFile("report_template.html")
	if err != nil {
		return fmt.Errorf("reading template: %w", err)
	}

	tmpl, err := template.New("report").Parse(string(tmplData))
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	data := buildReportData(artifacts, results, duration)

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating report file: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func buildReportData(artifacts []models.Artifact, results []models.CollectionResult, duration time.Duration) ReportData {
	hostname := ""
	osName := "macOS"
	osVersion := ""
	buildVersion := ""
	kernelVersion := ""
	serialNumber := ""
	architecture := ""
	numCPUs := ""
	uptime := ""

	// Extract system profile
	for _, a := range artifacts {
		if a.ArtifactType == "system_info" {
			hostname = a.Hostname
			osName = getStr(a.Data, "platform")
			osVersion = getStr(a.Data, "platform_version")
			buildVersion = getStr(a.Data, "build_version")
			kernelVersion = getStr(a.Data, "kernel_version")
			serialNumber = getStr(a.Data, "serial_number")
			architecture = getStr(a.Data, "architecture")
			numCPUs = getStr(a.Data, "num_cpus")
			if secs := getStr(a.Data, "uptime_seconds"); secs != "" {
				if d, err := time.ParseDuration(secs + "s"); err == nil {
					days := int(d.Hours()) / 24
					hours := int(d.Hours()) % 24
					uptime = fmt.Sprintf("%dd %dh", days, hours)
				}
			}
			break
		}
	}
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if osName == "" {
		osName = "macOS"
	}

	data := ReportData{
		Hostname:       hostname,
		OS:             osName,
		OSVersion:      osVersion,
		BuildVersion:   buildVersion,
		KernelVersion:  kernelVersion,
		SerialNumber:   serialNumber,
		Architecture:   architecture,
		NumCPUs:        numCPUs,
		Uptime:         uptime,
		GeneratedAt:    time.Now().Format("2006-01-02 15:04:05 MST"),
		TotalArtifacts: len(artifacts),
		CollectorsRun:  len(results),
		Duration:       duration.Round(time.Millisecond).String(),
	}

	// Count findings (risk score >= 40)
	for _, a := range artifacts {
		if a.RiskScore >= 40 {
			data.FindingsCount++
		}
	}

	// FOR518-aligned sections
	data.SecurityPosture = buildSecurityPosture(artifacts)
	data.TCCPermissions = buildTCC(artifacts)
	data.Environment = buildEnvironment(artifacts)
	data.Findings = buildFindings(artifacts)
	data.UserAccounts = buildUserAccounts(artifacts)
	data.SSHArtifacts = buildSSH(artifacts)
	data.Processes = buildProcesses(artifacts)
	data.InstalledApps = buildInstalledApps(artifacts)
	data.Persistence = buildPersistence(artifacts)
	data.BrowserHistory = buildActivityByTypes(artifacts, map[string]bool{
		"safari_history": true, "chrome_history": true,
	}, 5000)
	data.ShellHistory = buildActivityByTypes(artifacts, map[string]bool{
		"bash_history": true, "zsh_history": true,
	}, 5000)
	data.Downloads = buildActivityByTypes(artifacts, map[string]bool{
		"quarantine_event": true, "recent_file": true,
	}, 5000)
	data.AppUsage = buildActivityByTypes(artifacts, map[string]bool{
		"app_usage": true,
	}, 5000)
	data.Network = buildNetwork(artifacts)
	data.Logs = buildLogs(artifacts)

	// Timeline (cap at 10000 for HTML report; full data in SQLite)
	data.AllTimeline = buildTimeline(artifacts)
	if len(data.AllTimeline) > 10000 {
		data.AllTimeline = data.AllTimeline[len(data.AllTimeline)-10000:]
	}

	data.CollectorStats = buildCollectorStats(results)
	return data
}

func buildSecurityPosture(artifacts []models.Artifact) []SecurityPostureItem {
	var items []SecurityPostureItem

	posture := map[string]string{
		"gatekeeper_status": "Gatekeeper",
		"sip_status":        "System Integrity Protection (SIP)",
		"firewall_status":   "Application Firewall",
		"filevault_status":  "FileVault Disk Encryption",
	}

	found := make(map[string]bool)
	for _, a := range artifacts {
		if name, ok := posture[a.ArtifactType]; ok {
			enabled := false
			if v, ok := a.Data["enabled"]; ok {
				if b, ok := v.(bool); ok {
					enabled = b
				}
			}
			items = append(items, SecurityPostureItem{Name: name, Enabled: enabled})
			found[a.ArtifactType] = true
		}
	}

	return items
}

func buildFindings(artifacts []models.Artifact) []FindingRow {
	var findings []FindingRow

	for _, a := range artifacts {
		if a.RiskScore >= 40 { // medium and above
			dataJSON, _ := json.MarshalIndent(a.Data, "", "  ")
			findings = append(findings, FindingRow{
				ArtifactType: a.ArtifactType,
				CollectorID:  a.CollectorID,
				Summary:      Summarize(a),
				RiskScore:    a.RiskScore,
				Tags:         a.Tags,
				DataJSON:     string(dataJSON),
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].RiskScore > findings[j].RiskScore
	})

	return findings
}

func buildTimeline(artifacts []models.Artifact) []TimelineRow {
	type entry struct {
		t   time.Time
		row TimelineRow
	}
	var entries []entry

	for _, a := range artifacts {
		et := resolveEventTime(a)
		entries = append(entries, entry{
			t: et,
			row: TimelineRow{
				EventTime:    et.Format("2006-01-02 15:04:05"),
				ArtifactType: a.ArtifactType,
				CollectorID:  a.CollectorID,
				Summary:      Summarize(a),
			},
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].t.Before(entries[j].t)
	})

	rows := make([]TimelineRow, len(entries))
	for i, e := range entries {
		rows[i] = e.row
	}
	return rows
}

func resolveEventTime(a models.Artifact) time.Time {
	if a.EventTime != nil {
		return *a.EventTime
	}
	timeFields := []string{"visit_time", "last_visit_time", "mod_time", "timestamp", "event_time", "last_modified"}
	for _, field := range timeFields {
		if v, ok := a.Data[field]; ok {
			if s, ok := v.(string); ok {
				for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02 15:04:05"} {
					if t, err := time.Parse(layout, s); err == nil {
						return t
					}
				}
			}
		}
	}
	return a.Timestamp
}

func buildPersistence(artifacts []models.Artifact) []PersistenceRow {
	var rows []PersistenceRow

	persistTypes := map[string]bool{
		"user_launch_agent": true, "system_launch_agent": true, "system_launch_daemon": true,
		"login_item_btm": true, "login_item_backgrounditems": true,
		"user_crontab": true, "system_cron": true, "at_job": true,
		"system_extension": true, "kernel_extension": true, "library_extension": true,
	}

	for _, a := range artifacts {
		if !persistTypes[a.ArtifactType] {
			continue
		}
		name := getStr(a.Data, "name")
		if name == "" {
			name = getStr(a.Data, "identifier")
		}
		path := getStr(a.Data, "path")
		program := getStr(a.Data, "program")
		if program == "" {
			program = getStr(a.Data, "program_arguments")
		}
		if program == "" {
			program = getStr(a.Data, "content")
		}
		rows = append(rows, PersistenceRow{
			ArtifactType: a.ArtifactType,
			Name:         name,
			Path:         path,
			Program:      program,
			RiskScore:    a.RiskScore,
		})
	}

	return rows
}

func buildNetwork(artifacts []models.Artifact) []NetworkRow {
	var rows []NetworkRow

	netTypes := map[string]bool{
		"network_connection": true, "network_interface": true,
		"arp_entry": true, "open_network_file": true,
		"routing_table_entry": true, "dns_config": true, "dns_config_scutil": true,
	}

	for _, a := range artifacts {
		if !netTypes[a.ArtifactType] {
			continue
		}
		rows = append(rows, NetworkRow{
			ArtifactType: a.ArtifactType,
			Summary:      Summarize(a),
			RiskScore:    a.RiskScore,
		})
	}

	// Limit to 200 for report readability
	if len(rows) > 200 {
		rows = rows[:200]
	}

	return rows
}

func buildProcesses(artifacts []models.Artifact) []ProcessRow {
	var rows []ProcessRow

	for _, a := range artifacts {
		if a.ArtifactType != "running_process" {
			continue
		}
		rows = append(rows, ProcessRow{
			PID:       getStr(a.Data, "pid"),
			PPID:      getStr(a.Data, "ppid"),
			Name:      getStr(a.Data, "name"),
			User:      getStr(a.Data, "username"),
			Exe:       getStr(a.Data, "exe"),
			CPU:       getStr(a.Data, "cpu_percent"),
			Mem:       getStr(a.Data, "memory_percent"),
			RiskScore: a.RiskScore,
		})
	}

	// Sort: flagged processes first
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].RiskScore > rows[j].RiskScore
	})

	return rows
}

func buildActivityByTypes(artifacts []models.Artifact, types map[string]bool, limit int) []UserActivityRow {
	// Group by type first so each type gets fair representation
	byType := make(map[string][]UserActivityRow)
	for _, a := range artifacts {
		if !types[a.ArtifactType] {
			continue
		}
		et := resolveEventTime(a)
		byType[a.ArtifactType] = append(byType[a.ArtifactType], UserActivityRow{
			ArtifactType: a.ArtifactType,
			Summary:      Summarize(a),
			EventTime:    et.Format("2006-01-02 15:04:05"),
		})
	}

	// Cap per type, then merge and sort
	perType := limit
	if len(byType) > 0 {
		perType = limit / len(byType)
		if perType < 1 {
			perType = 1
		}
	}
	var rows []UserActivityRow
	for _, typed := range byType {
		sort.Slice(typed, func(i, j int) bool {
			return typed[i].EventTime > typed[j].EventTime
		})
		if len(typed) > perType {
			typed = typed[:perType]
		}
		rows = append(rows, typed...)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].EventTime > rows[j].EventTime
	})
	return rows
}

func buildUserAccounts(artifacts []models.Artifact) []UserAccountRow {
	var rows []UserAccountRow
	for _, a := range artifacts {
		if a.ArtifactType != "user_account" {
			continue
		}
		rows = append(rows, UserAccountRow{
			Username: getStr(a.Data, "username"),
			RealName: getStr(a.Data, "real_name"),
			UID:      getStr(a.Data, "uid"),
			Home:     getStr(a.Data, "home_dir"),
			Shell:    getStr(a.Data, "shell"),
		})
	}
	return rows
}

func buildTCC(artifacts []models.Artifact) []TCCRow {
	var rows []TCCRow
	for _, a := range artifacts {
		if a.ArtifactType != "tcc_permission" {
			continue
		}
		rows = append(rows, TCCRow{
			Service:   getStr(a.Data, "service"),
			Client:    getStr(a.Data, "client"),
			AuthValue: getStr(a.Data, "auth_value"),
			DBType:    getStr(a.Data, "database_type"),
		})
	}
	return rows
}

func buildSSH(artifacts []models.Artifact) []SSHRow {
	var rows []SSHRow
	sshTypes := map[string]bool{
		"ssh_private_key": true, "ssh_public_key": true,
		"ssh_config": true, "ssh_known_host": true, "ssh_authorized_key": true,
	}
	for _, a := range artifacts {
		if !sshTypes[a.ArtifactType] {
			continue
		}
		rows = append(rows, SSHRow{
			ArtifactType: a.ArtifactType,
			Path:         getStr(a.Data, "path"),
			Detail:       Summarize(a),
			RiskScore:    a.RiskScore,
		})
	}
	return rows
}

func buildInstalledApps(artifacts []models.Artifact) []InstalledAppRow {
	var rows []InstalledAppRow
	for _, a := range artifacts {
		source := ""
		switch a.ArtifactType {
		case "system_application":
			source = "System"
		case "user_application":
			source = "User"
		default:
			continue
		}
		rows = append(rows, InstalledAppRow{
			Name:    getStr(a.Data, "name"),
			Path:    getStr(a.Data, "path"),
			ModTime: getStr(a.Data, "mod_time"),
			Source:  source,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Name < rows[j].Name
	})
	return rows
}

func buildLogs(artifacts []models.Artifact) []LogRow {
	var rows []LogRow
	logTypes := map[string]bool{
		"unified_log_security": true, "unified_log_network": true,
		"unified_log_process": true, "unified_log_errors": true,
		"user_crash_report": true, "system_crash_report": true,
		"install_log": true,
	}
	for _, a := range artifacts {
		if !logTypes[a.ArtifactType] {
			continue
		}
		et := resolveEventTime(a)
		rows = append(rows, LogRow{
			ArtifactType: a.ArtifactType,
			Summary:      Summarize(a),
			Time:         et.Format("2006-01-02 15:04:05"),
		})
	}
	if len(rows) > 500 {
		rows = rows[:500]
	}
	return rows
}

func buildEnvironment(artifacts []models.Artifact) []EnvironmentRow {
	var rows []EnvironmentRow
	for _, a := range artifacts {
		if a.ArtifactType != "env_variable" && a.ArtifactType != "env_variable_suspicious" {
			continue
		}
		rows = append(rows, EnvironmentRow{
			Key:       getStr(a.Data, "key"),
			Value:     getStr(a.Data, "value"),
			Reason:    getStr(a.Data, "suspicious_reason"),
			RiskScore: a.RiskScore,
		})
	}
	// Suspicious first
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].RiskScore > rows[j].RiskScore
	})
	return rows
}

func buildCollectorStats(results []models.CollectionResult) []CollectorStat {
	var stats []CollectorStat

	for _, r := range results {
		stats = append(stats, CollectorStat{
			ID:       r.CollectorID,
			Count:    len(r.Artifacts),
			Duration: r.Duration.Round(time.Millisecond).String(),
			Success:  r.Error == nil,
		})
	}

	return stats
}

func getStr(d map[string]interface{}, key string) string {
	if v, ok := d[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// FormatRawJSON returns a pretty-printed JSON representation of artifacts (limited)
func FormatRawJSON(artifacts []models.Artifact) string {
	// Limit to first 50 artifacts for display
	limit := artifacts
	if len(limit) > 50 {
		limit = limit[:50]
	}

	data, err := json.MarshalIndent(limit, "", "  ")
	if err != nil {
		return "Error formatting JSON"
	}

	result := string(data)
	// Escape HTML
	result = strings.ReplaceAll(result, "<", "&lt;")
	result = strings.ReplaceAll(result, ">", "&gt;")
	return result
}
