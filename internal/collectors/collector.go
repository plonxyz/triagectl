package collectors

import (
	"context"
	"github.com/plonxyz/triagectl/internal/models"
)

// Collector interface that all artifact collectors must implement
type Collector interface {
	// ID returns a unique identifier for this collector
	ID() string

	// Name returns a human-readable name
	Name() string

	// Description returns what this collector does
	Description() string

	// RequiresRoot indicates if root privileges are needed
	RequiresRoot() bool

	// Collect performs the artifact collection
	Collect(ctx context.Context) ([]models.Artifact, error)
}

// Registry holds all available collectors
var Registry = []Collector{
	// Basic System Info
	&SystemInfoCollector{},
	&RunningProcessesCollector{},
	&NetworkConnectionsCollector{},
	&NetworkInterfacesCollector{},
	&UserAccountsCollector{},

	// Persistence Mechanisms
	&LaunchAgentsCollector{},
	&ScheduledTasksCollector{},
	&LoginItemsCollector{},

	// User Activity
	&BrowserHistoryCollector{},
	&RecentFilesCollector{},
	&ShellHistoryCollector{},
	&QuarantineEventsCollector{},
	&KnowledgeCCollector{},

	// Security & Privacy
	&TCCCollector{},
	&SSHCollector{},
	&GatekeeperCollector{},
	&FirewallCollector{},
	&FileVaultCollector{},

	// System Extensions
	&ExtensionsCollector{},

	// Network
	&ARPCacheCollector{},
	&OpenFilesCollector{},

	// Environment
	&EnvironmentCollector{},

	// Applications & Logs
	&InstalledAppsCollector{},
	&SystemLogsCollector{},
	&UnifiedLogsCollector{},

	// Advanced (requires root or special permissions)
	&FSEventsCollector{},
}
