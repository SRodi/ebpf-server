// Package manager provides program management functionality.
package programs

import (
	"context"
	"fmt"
	"sync"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/events"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// Manager orchestrates multiple eBPF programs.
type Manager struct {
	programs    []core.Program
	eventStream *events.MergedStream
	running     bool
	mu          sync.RWMutex
}

// NewManager creates a new program manager.
func NewManager() *Manager {
	return &Manager{
		programs: make([]core.Program, 0),
	}
}

// RegisterProgram adds a program to the manager.
func (m *Manager) RegisterProgram(program core.Program) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Check for nil program
	if program == nil {
		return fmt.Errorf("cannot register nil program")
	}
	
	// Check for duplicate names
	for _, p := range m.programs {
		if p.Name() == program.Name() {
			return fmt.Errorf("program with name %s already registered", program.Name())
		}
	}
	
	m.programs = append(m.programs, program)
	logger.Debugf("Registered program: %s", program.Name())
	
	return nil
}

// LoadAll loads all registered programs.
func (m *Manager) LoadAll(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	logger.Debugf("Loading %d eBPF programs", len(m.programs))
	
	for _, program := range m.programs {
		if err := program.Load(ctx); err != nil {
			return fmt.Errorf("failed to load program %s: %w", program.Name(), err)
		}
	}
	
	logger.Info("All eBPF programs loaded successfully")
	return nil
}

// AttachAll attaches all loaded programs.
func (m *Manager) AttachAll(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	logger.Debugf("Attaching %d eBPF programs", len(m.programs))
	
	// Collect event streams from all programs
	var streams []core.EventStream
	
	for _, program := range m.programs {
		if !program.IsLoaded() {
			return fmt.Errorf("program %s is not loaded", program.Name())
		}
		
		if err := program.Attach(ctx); err != nil {
			return fmt.Errorf("failed to attach program %s: %w", program.Name(), err)
		}
		
		streams = append(streams, program.EventStream())
	}
	
	// Create merged event stream
	m.eventStream = events.NewMergedStream(streams)
	m.running = true
	
	logger.Info("All eBPF programs attached successfully")
	return nil
}

// DetachAll detaches all programs.
func (m *Manager) DetachAll(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if !m.running {
		return nil
	}
	
	logger.Debugf("Detaching %d eBPF programs", len(m.programs))
	
	// Close merged event stream
	if m.eventStream != nil {
		m.eventStream.Close()
		m.eventStream = nil
	}
	
	// Detach all programs
	for _, program := range m.programs {
		if err := program.Detach(ctx); err != nil {
			logger.Errorf("Error detaching program %s: %v", program.Name(), err)
		}
	}
	
	m.running = false
	logger.Info("All eBPF programs detached")
	
	return nil
}

// Programs returns all registered programs.
func (m *Manager) Programs() []core.Program {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Return a copy to prevent external modifications
	programs := make([]core.Program, len(m.programs))
	copy(programs, m.programs)
	
	return programs
}

// EventStream returns the unified event stream.
func (m *Manager) EventStream() core.EventStream {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	return m.eventStream
}

// IsRunning returns true if the manager is active.
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	return m.running
}

// GetProgramStatus returns the status of all programs.
func (m *Manager) GetProgramStatus() []core.ProgramStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	status := make([]core.ProgramStatus, len(m.programs))
	
	for i, program := range m.programs {
		totalEvents, droppedEvents, dropRate := program.GetStats()
		
		status[i] = core.ProgramStatus{
			Name:         program.Name(),
			Description:  program.Description(),
			Loaded:       program.IsLoaded(),
			Attached:     program.IsAttached(),
			EventCount:   int64(totalEvents),
			DroppedCount: int64(droppedEvents),
			DropRate:     dropRate,
		}
	}
	
	return status
}
