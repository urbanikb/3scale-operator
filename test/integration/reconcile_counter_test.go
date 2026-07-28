package integration

import (
	"fmt"
	"strings"
	"sync"

	"go.uber.org/zap/zapcore"
)

// counterState is the single shared mutable core of a ReconcileCounter tree.
// All ReconcileCounter instances produced by With() point to the same counterState,
// so counts accumulate correctly regardless of which logger variant does the write.
// mu protects updateCounts; deploymentNames is read-only after construction.
type counterState struct {
	deploymentNames map[string]bool
	updateCounts    map[string]int
	mu              sync.Mutex
}

// ReconcileCounter wraps a zapcore.Core to count Deployment update log entries
// for a fixed set of monitored deployment names. Counts are global (not keyed
// by CR instance), so Reset must be called between measurement windows.
type ReconcileCounter struct {
	zapcore.Core
	state *counterState
}

// NewReconcileCounter creates a new ReconcileCounter wrapping the given core.
func NewReconcileCounter(core zapcore.Core, deploymentNames []string) *ReconcileCounter {
	nameMap := make(map[string]bool, len(deploymentNames))
	for _, name := range deploymentNames {
		nameMap[name] = true
	}
	return &ReconcileCounter{
		Core: core,
		state: &counterState{
			deploymentNames: nameMap,
			updateCounts:    make(map[string]int),
		},
	}
}

// With returns a new ReconcileCounter wrapping the inner core-with-fields,
// sharing the same counter state.
func (rc *ReconcileCounter) With(fields []zapcore.Field) zapcore.Core {
	return &ReconcileCounter{
		Core:  rc.Core.With(fields),
		state: rc.state,
	}
}

// Check ensures rc.Write is called (not the inner core's Write) for enabled entries.
func (rc *ReconcileCounter) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if rc.Core.Enabled(entry.Level) {
		return ce.AddCore(entry, rc)
	}
	return ce
}

// Write intercepts "Updated object 'v1.Deployment/<name>'" log entries and
// increments the per-deployment counter.
func (rc *ReconcileCounter) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	if strings.Contains(entry.Message, "Updated object 'v1.Deployment/") {
		parts := strings.Split(entry.Message, "v1.Deployment/")
		if len(parts) == 2 {
			deploymentName := strings.TrimSuffix(parts[1], "'")
			if rc.state.deploymentNames[deploymentName] {
				rc.state.mu.Lock()
				rc.state.updateCounts[deploymentName]++
				rc.state.mu.Unlock()
			}
		}
	}
	return rc.Core.Write(entry, fields)
}

// Reset clears all accumulated counts. Call before each measurement window.
func (rc *ReconcileCounter) Reset() {
	rc.state.mu.Lock()
	defer rc.state.mu.Unlock()
	rc.state.updateCounts = make(map[string]int)
}

// GetUpdateCounts returns a copy of the per-deployment update counts.
func (rc *ReconcileCounter) GetUpdateCounts() map[string]int {
	rc.state.mu.Lock()
	defer rc.state.mu.Unlock()
	counts := make(map[string]int, len(rc.state.updateCounts))
	for k, v := range rc.state.updateCounts {
		counts[k] = v
	}
	return counts
}

// GetTotalUpdates returns the total number of deployment updates recorded.
func (rc *ReconcileCounter) GetTotalUpdates() int {
	rc.state.mu.Lock()
	defer rc.state.mu.Unlock()
	total := 0
	for _, v := range rc.state.updateCounts {
		total += v
	}
	return total
}

// GetReport returns a human-readable breakdown of all recorded updates.
func (rc *ReconcileCounter) GetReport() string {
	rc.state.mu.Lock()
	defer rc.state.mu.Unlock()
	if len(rc.state.updateCounts) == 0 {
		return "No deployment updates detected"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Deployment update counts:\n")
	for depName, count := range rc.state.updateCounts {
		fmt.Fprintf(&sb, "  %s: %d updates\n", depName, count)
	}
	return sb.String()
}
