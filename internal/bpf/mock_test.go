package bpf

import (
	"context"
	"errors"
	"time"
	
	"github.com/srodi/ebpf-server/pkg/logger"
)

// Test errors
var (
	ErrProgramNotLoaded   = errors.New("program not loaded")
	ErrProgramNotAttached = errors.New("program not attached")
)

// MockEvent implements BPFEvent for testing
type MockEvent struct {
	BaseEvent
	eventType string
}

func (e *MockEvent) GetEventType() string {
	return e.eventType
}

// MockProgram implements BPFProgram for testing
type MockProgram struct {
	name        string
	description string
	objectPath  string
	loaded      bool
	attached    bool
	running     bool
	eventChan   chan BPFEvent
	storage     EventStorage
	loadError   error
	attachError error
	startError  error
}

func NewMockProgram(name, desc string, storage EventStorage) *MockProgram {
	return &MockProgram{
		name:        name,
		description: desc,
		objectPath:  "mock/" + name + ".o",
		eventChan:   make(chan BPFEvent, 100),
		storage:     storage,
	}
}

func (p *MockProgram) GetName() string        { return p.name }
func (p *MockProgram) GetDescription() string { return p.description }
func (p *MockProgram) GetObjectPath() string  { return p.objectPath }

func (p *MockProgram) Load() error {
	if p.loadError != nil {
		return p.loadError
	}
	p.loaded = true
	return nil
}

func (p *MockProgram) Attach() error {
	if !p.loaded {
		return ErrProgramNotLoaded
	}
	if p.attachError != nil {
		return p.attachError
	}
	p.attached = true
	return nil
}

func (p *MockProgram) Start(ctx context.Context) error {
	if !p.attached {
		return ErrProgramNotAttached
	}
	if p.startError != nil {
		return p.startError
	}
	p.running = true
	return nil
}

func (p *MockProgram) Stop() error {
	p.running = false
	close(p.eventChan)
	return nil
}

func (p *MockProgram) IsRunning() bool { return p.running }

func (p *MockProgram) GetEventChannel() <-chan BPFEvent { return p.eventChan }

func (p *MockProgram) GetSummary(pid uint32, command string, durationSeconds int) int {
	since := time.Now().Add(-time.Duration(durationSeconds) * time.Second)
	return p.storage.Count(pid, command, p.name, since)
}

func (p *MockProgram) GetAllEvents() map[uint32][]BPFEvent {
	allEvents := p.storage.GetAll()
	if events, exists := allEvents[p.name]; exists {
		return events
	}
	return make(map[uint32][]BPFEvent)
}

// SetErrors allows setting errors for testing error conditions
func (p *MockProgram) SetErrors(loadErr, attachErr, startErr error) {
	p.loadError = loadErr
	p.attachError = attachErr
	p.startError = startErr
}

// SendEvent sends a mock event for testing
func (p *MockProgram) SendEvent(event BPFEvent) {
	// Store the event (like real programs do)
	if p.storage != nil {
		if err := p.storage.Store(event); err != nil {
			// In tests, we can just log this error since it's not critical
			logger.Debugf("Failed to store mock event: %v", err)
		}
	}
	
	// Send to channel for aggregation
	select {
	case p.eventChan <- event:
	default:
		// Channel full, ignore
	}
}
