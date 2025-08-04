package bpf

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// Manager implements BPFManager and manages multiple eBPF programs
type Manager struct {
	mu       sync.RWMutex
	programs map[string]BPFProgram
	storage  EventStorage
	
	// Event aggregation
	eventChan chan BPFEvent
	ctx       context.Context
	cancel    context.CancelFunc
	running   bool
	
	// Cleanup
	cleanupTicker *time.Ticker
	cleanupDone   chan struct{}
}

// NewManager creates a new BPF program manager
func NewManager() *Manager {
	return &Manager{
		programs:  make(map[string]BPFProgram),
		storage:   NewInMemoryStorage(),
		eventChan: make(chan BPFEvent, 10000), // Large buffer for aggregated events
	}
}

// RegisterProgram adds a new eBPF program to be managed
func (m *Manager) RegisterProgram(program BPFProgram) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := program.GetName()
	if _, exists := m.programs[name]; exists {
		return fmt.Errorf("program '%s' already registered", name)
	}

	m.programs[name] = program
	logger.Infof("Registered eBPF program: %s - %s", name, program.GetDescription())
	return nil
}

// UnregisterProgram removes an eBPF program from management
func (m *Manager) UnregisterProgram(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	program, exists := m.programs[name]
	if !exists {
		return fmt.Errorf("program '%s' not found", name)
	}

	// Stop the program if it's running
	if program.IsRunning() {
		if err := program.Stop(); err != nil {
			logger.Errorf("Error stopping program '%s': %v", name, err)
		}
	}

	delete(m.programs, name)
	logger.Infof("Unregistered eBPF program: %s", name)
	return nil
}

// LoadAll loads all registered programs
func (m *Manager) LoadAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errors []string
	loaded := 0

	for name, program := range m.programs {
		if err := program.Load(); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
			logger.Errorf("Failed to load program '%s': %v", name, err)
		} else {
			loaded++
			logger.Infof("Loaded program '%s'", name)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to load %d programs: %s", len(errors), strings.Join(errors, "; "))
	}

	logger.Infof("Successfully loaded %d eBPF programs", loaded)
	return nil
}

// AttachAll attaches all loaded programs
func (m *Manager) AttachAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errors []string
	attached := 0

	for name, program := range m.programs {
		if err := program.Attach(); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
			logger.Errorf("Failed to attach program '%s': %v", name, err)
		} else {
			attached++
			logger.Infof("Attached program '%s'", name)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to attach %d programs: %s", len(errors), strings.Join(errors, "; "))
	}

	logger.Infof("Successfully attached %d eBPF programs", attached)
	return nil
}

// StartAll starts event processing for all programs
func (m *Manager) StartAll() error {
	if m.running {
		return fmt.Errorf("manager already running")
	}

	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.running = true

	// Start cleanup routine
	m.cleanupTicker = time.NewTicker(5 * time.Minute) // Clean up every 5 minutes
	m.cleanupDone = make(chan struct{})
	go m.cleanupRoutine()

	// Start event aggregation
	go m.aggregateEvents()

	m.mu.RLock()
	defer m.mu.RUnlock()

	var errors []string
	started := 0

	for name, program := range m.programs {
		if err := program.Start(m.ctx); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
			logger.Errorf("Failed to start program '%s': %v", name, err)
		} else {
			started++
			logger.Infof("Started program '%s'", name)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to start %d programs: %s", len(errors), strings.Join(errors, "; "))
	}

	logger.Infof("Successfully started %d eBPF programs", started)
	return nil
}

// StopAll stops all programs and cleans up resources
func (m *Manager) StopAll() error {
	if !m.running {
		return nil
	}

	// Cancel context to stop all programs
	if m.cancel != nil {
		m.cancel()
	}

	// Stop cleanup routine
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
		close(m.cleanupDone)
	}

	m.mu.RLock()
	programs := make(map[string]BPFProgram)
	for name, program := range m.programs {
		programs[name] = program
	}
	m.mu.RUnlock()

	var errors []string
	stopped := 0

	for name, program := range programs {
		if err := program.Stop(); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
			logger.Errorf("Error stopping program '%s': %v", name, err)
		} else {
			stopped++
			logger.Infof("Stopped program '%s'", name)
		}
	}

	m.running = false
	close(m.eventChan)

	if len(errors) > 0 {
		return fmt.Errorf("errors stopping %d programs: %s", len(errors), strings.Join(errors, "; "))
	}

	logger.Infof("Successfully stopped %d eBPF programs", stopped)
	return nil
}

// GetProgram returns a specific program by name
func (m *Manager) GetProgram(name string) (BPFProgram, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	program, exists := m.programs[name]
	return program, exists
}

// ListPrograms returns a list of all registered program names
func (m *Manager) ListPrograms() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.programs))
	for name := range m.programs {
		names = append(names, name)
	}
	return names
}

// IsAvailable checks if eBPF is available on the current system
func (m *Manager) IsAvailable() bool {
	// On macOS, eBPF is not available
	if strings.Contains(strings.ToLower(os.Getenv("GOOS")), "darwin") {
		logger.Info("eBPF is not available on macOS - running in mock mode")
		return false
	}

	// Try to remove memory limit for eBPF - this will fail if not supported
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Infof("Failed to remove memory limit for eBPF: %v", err)
		return false
	}

	// Check if we can access /sys/fs/bpf (BPF filesystem)
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		logger.Info("BPF filesystem not available")
		return false
	}

	return true
}

// GetAggregatedEvents returns events from all programs combined
func (m *Manager) GetAggregatedEvents() <-chan BPFEvent {
	return m.eventChan
}

// GetStorage returns the event storage instance
func (m *Manager) GetStorage() EventStorage {
	return m.storage
}

// aggregateEvents collects events from all programs and forwards them
func (m *Manager) aggregateEvents() {
	logger.Info("Starting event aggregation...")

	// Create a map to track program event channels
	programChannels := make(map[string]<-chan BPFEvent)

	// Update program channels when programs are added/removed
	updateChannels := func() {
		m.mu.RLock()
		defer m.mu.RUnlock()

		// Add new channels
		for name, program := range m.programs {
			if _, exists := programChannels[name]; !exists {
				programChannels[name] = program.GetEventChannel()
			}
		}

		// Remove channels for unregistered programs
		for name := range programChannels {
			if _, exists := m.programs[name]; !exists {
				delete(programChannels, name)
			}
		}
	}

	ticker := time.NewTicker(1 * time.Second) // Update channels periodically
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			logger.Info("Stopping event aggregation...")
			return
		case <-ticker.C:
			updateChannels()
		default:
			// Non-blocking select to read from all program channels
			updateChannels()
			for name, ch := range programChannels {
				select {
				case event, ok := <-ch:
					if !ok {
						delete(programChannels, name)
						continue
					}
					// Forward event to aggregated channel
					select {
					case m.eventChan <- event:
					default:
						logger.Infof("Aggregated event channel full, dropping event from %s", name)
					}
				default:
					// No event available from this program
				}
			}
			// Small sleep to avoid busy waiting
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// cleanupRoutine periodically cleans up old events
func (m *Manager) cleanupRoutine() {
	logger.Info("Starting storage cleanup routine...")

	for {
		select {
		case <-m.cleanupDone:
			logger.Info("Stopping storage cleanup routine...")
			return
		case <-m.cleanupTicker.C:
			// Clean up events older than 1 hour
			removed := m.storage.Cleanup(1 * time.Hour)
			if removed > 0 {
				logger.Debugf("Cleaned up %d old events", removed)
			}
		}
	}
}
