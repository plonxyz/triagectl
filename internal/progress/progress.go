package progress

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Tracker displays a progress bar when stdout is a TTY, line-by-line otherwise
type Tracker struct {
	mu       sync.Mutex
	total    int
	done     int
	failed   int
	current  string
	isTTY    bool
}

// NewTracker creates a progress tracker
func NewTracker(total int) *Tracker {
	return &Tracker{
		total: total,
		isTTY: isTerminal(),
	}
}

func isTerminal() bool {
	_, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	return err == nil
}

// Start prints the current collector being run (non-TTY mode)
func (t *Tracker) Start(collectorName string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.current = collectorName
	if t.isTTY {
		t.render()
	} else {
		fmt.Printf("  [*] Running: %s\n", collectorName)
	}
}

// Success marks a collector as complete
func (t *Tracker) Success(collectorID string, count int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.done++
	if t.isTTY {
		t.render()
	} else {
		if count > 0 {
			fmt.Printf("  [+] %s: collected %d artifacts\n", collectorID, count)
		} else {
			fmt.Printf("  [+] %s: no artifacts found\n", collectorID)
		}
	}
}

// Fail marks a collector as failed
func (t *Tracker) Fail(collectorID string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.done++
	t.failed++
	if t.isTTY {
		t.render()
	} else {
		fmt.Printf("  [!] %s failed: %v\n", collectorID, err)
	}
}

// Finish clears the progress line (TTY mode)
func (t *Tracker) Finish() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.isTTY {
		// Clear the line
		fmt.Print("\r\033[K")
	}
}

func (t *Tracker) render() {
	barWidth := 30
	completed := t.done
	if t.total == 0 {
		return
	}
	filled := (completed * barWidth) / t.total
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("=", filled)
	if filled < barWidth {
		bar += ">"
		bar += strings.Repeat(" ", barWidth-filled-1)
	}

	failStr := ""
	if t.failed > 0 {
		failStr = fmt.Sprintf(" | %d failed", t.failed)
	}

	line := fmt.Sprintf("\r  [%s] %d/%d | Running: %s%s",
		bar, completed, t.total, t.current, failStr)

	// Truncate to terminal width if possible
	if len(line) > 100 {
		line = line[:100]
	}
	fmt.Print("\033[K" + line)
}
