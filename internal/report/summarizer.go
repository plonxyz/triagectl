package report

import (
	"fmt"
	"strings"

	"github.com/plonxyz/triagectl/internal/models"
)

// Summarize returns a human-readable one-line summary for an artifact
func Summarize(a models.Artifact) string {
	d := a.Data

	switch a.ArtifactType {
	// Persistence
	case "user_launch_agent", "system_launch_agent", "system_launch_daemon":
		return fmt.Sprintf("Launch agent: %s at %s", getString(d, "name"), getString(d, "path"))
	case "login_item_btm":
		return fmt.Sprintf("Login item (BTM): %s", getString(d, "Name"))
	case "login_item_backgrounditems":
		return fmt.Sprintf("Background login item: %s", getString(d, "path"))
	case "user_crontab", "system_cron":
		return fmt.Sprintf("Cron job: %s", getString(d, "entry"))
	case "at_job":
		return fmt.Sprintf("At job: %s", getString(d, "job_id"))

	// Security posture
	case "gatekeeper_status":
		if getBool(d, "enabled") {
			return "Gatekeeper: enabled"
		}
		return "Gatekeeper: DISABLED"
	case "sip_status":
		if getBool(d, "enabled") {
			return "SIP: enabled"
		}
		return "SIP: DISABLED"
	case "xprotect_version":
		return fmt.Sprintf("XProtect version: %s", getString(d, "version"))
	case "firewall_status":
		if getBool(d, "enabled") {
			return "Firewall: enabled"
		}
		return "Firewall: DISABLED"
	case "filevault_status":
		if getBool(d, "enabled") {
			return "FileVault: enabled"
		}
		return "FileVault: DISABLED"
	case "apfs_encryption":
		if getBool(d, "encrypted") {
			return "APFS encryption: enabled"
		}
		return "APFS encryption: not detected"

	// Process
	case "running_process":
		return fmt.Sprintf("Process: %s (PID %s) by %s", getString(d, "name"), getString(d, "pid"), getString(d, "username"))

	// Network
	case "network_connection":
		return fmt.Sprintf("Connection: %s:%s -> %s:%s (%s)",
			getString(d, "local_addr"), getString(d, "local_port"),
			getString(d, "remote_addr"), getString(d, "remote_port"),
			getString(d, "status"))
	case "open_network_file":
		return fmt.Sprintf("Open file: %s (PID %s) %s", getString(d, "command"), getString(d, "pid"), getString(d, "name"))
	case "arp_entry":
		return fmt.Sprintf("ARP: %s -> %s on %s", getString(d, "ip"), getString(d, "mac"), getString(d, "interface"))
	case "network_interface":
		return fmt.Sprintf("Interface: %s", getString(d, "name"))

	// User activity
	case "safari_history", "chrome_history":
		return fmt.Sprintf("Visit: %s (%s)", getString(d, "title"), truncate(getString(d, "url"), 60))
	case "bash_history", "zsh_history":
		return fmt.Sprintf("Shell: %s", truncate(getString(d, "command"), 80))
	case "recent_file":
		return fmt.Sprintf("Recent file: %s", getString(d, "name"))
	case "quarantine_event":
		return fmt.Sprintf("Quarantine: %s from %s", getString(d, "agent_name"), truncate(getString(d, "origin_url"), 60))
	case "app_usage":
		return fmt.Sprintf("App usage: %s", getString(d, "app_name"))

	// SSH
	case "ssh_private_key", "ssh_public_key":
		return fmt.Sprintf("SSH key: %s (%s)", getString(d, "path"), getString(d, "key_type"))
	case "ssh_authorized_key":
		return fmt.Sprintf("Authorized key: %s", truncate(getString(d, "key"), 50))
	case "ssh_known_host":
		entry := getString(d, "entry")
		host := entry
		if idx := strings.Index(entry, " "); idx > 0 {
			host = entry[:idx]
		}
		return fmt.Sprintf("Known host: %s", host)

	// Extensions
	case "system_extension":
		return fmt.Sprintf("System extension: %s", getString(d, "identifier"))
	case "kernel_extension":
		return fmt.Sprintf("Kernel extension: %s", getString(d, "name"))
	case "library_extension":
		return fmt.Sprintf("Library extension: %s", getString(d, "name"))

	// Environment
	case "env_variable_suspicious":
		return fmt.Sprintf("Suspicious env: %s=%s (%s)", getString(d, "key"), truncate(getString(d, "value"), 40), getString(d, "suspicious_reason"))
	case "env_variable":
		return fmt.Sprintf("Env: %s", getString(d, "key"))

	// TCC
	case "tcc_permission":
		return fmt.Sprintf("TCC: %s granted to %s", getString(d, "service"), getString(d, "client"))

	// Apps
	case "system_application", "user_application":
		return fmt.Sprintf("App: %s", getString(d, "name"))

	// Logs
	case "user_crash_report", "system_crash_report":
		return fmt.Sprintf("Crash report: %s", getString(d, "filename"))
	case "install_log":
		return fmt.Sprintf("Install log: %s", getString(d, "path"))
	case "unified_log_security", "unified_log_network", "unified_log_process", "unified_log_errors":
		msg := getString(d, "event_message")
		if msg == "" {
			msg = getString(d, "log_entry")
		}
		proc := getString(d, "process")
		if proc != "" {
			return fmt.Sprintf("[%s] %s: %s", getString(d, "category"), proc, truncate(msg, 60))
		}
		return fmt.Sprintf("[%s] %s", getString(d, "category"), truncate(msg, 60))

	// System info
	case "system_info":
		return fmt.Sprintf("System: %s %s", getString(d, "platform"), getString(d, "platform_version"))

	default:
		// Generic fallback
		if name := getString(d, "name"); name != "" {
			return fmt.Sprintf("%s: %s", strings.ReplaceAll(a.ArtifactType, "_", " "), name)
		}
		return strings.ReplaceAll(a.ArtifactType, "_", " ")
	}
}

func getString(d map[string]interface{}, key string) string {
	if v, ok := d[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func getBool(d map[string]interface{}, key string) bool {
	if v, ok := d[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
