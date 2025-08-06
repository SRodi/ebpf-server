// Package system provides the main orchestration for the eBPF monitoring system.
package system

import (
	"context"
	"fmt"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/programs"
	"github.com/srodi/ebpf-server/internal/programs/connection"
	"github.com/srodi/ebpf-server/internal/programs/packet_drop"
	"github.com/srodi/ebpf-server/internal/storage"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// System is the main orchestrator for the eBPF monitoring system.
type System struct {
	manager core.Manager
	storage core.EventSink
}

// NewSystem creates a new eBPF monitoring system.
func NewSystem() *System {
	manager := programs.NewManager()
	memStorage := storage.NewMemoryStorage()

	return &System{
		manager: manager,
		storage: memStorage,
	}
}

// Initialize sets up the system with all available programs.
func (s *System) Initialize() error {
	logger.Info("🚀 Initializing eBPF monitoring system")

	// Register connection monitoring program
	connProgram := connection.NewProgram()
	if err := s.manager.RegisterProgram(connProgram); err != nil {
		return fmt.Errorf("failed to register connection program: %w", err)
	}
	logger.Debugf("✅ Registered connection monitoring program")

	// Register packet drop monitoring program
	dropProgram := packet_drop.NewProgram()
	if err := s.manager.RegisterProgram(dropProgram); err != nil {
		return fmt.Errorf("failed to register packet drop program: %w", err)
	}
	logger.Debugf("✅ Registered packet drop monitoring program")

	logger.Info("🚀 eBPF monitoring system initialized successfully")
	return nil
}

// Start loads and attaches all programs, then starts event collection.
func (s *System) Start(ctx context.Context) error {
	logger.Info("🔧 Starting eBPF monitoring system")

	// Load all programs
	if err := s.manager.LoadAll(ctx); err != nil {
		return fmt.Errorf("failed to load programs: %w", err)
	}
	logger.Debugf("✅ All eBPF programs loaded")

	// Attach all programs
	if err := s.manager.AttachAll(ctx); err != nil {
		return fmt.Errorf("failed to attach programs: %w", err)
	}
	logger.Debugf("✅ All eBPF programs attached to kernel")

	// Start consuming events and storing them
	eventStream := s.manager.EventStream()
	if eventStream != nil {
		s.storage = storage.NewStorageWithSink(s.storage, eventStream)
		logger.Debugf("✅ Event storage pipeline started")
	}

	logger.Info("🎯 eBPF monitoring system started and ready to capture events!")
	return nil
}

// Stop detaches all programs and cleans up resources.
func (s *System) Stop(ctx context.Context) error {
	logger.Info("Stopping eBPF monitoring system")

	// Stop storage sink
	if storageWithSink, ok := s.storage.(*storage.StorageWithSink); ok {
		storageWithSink.Close()
	}

	// Detach all programs
	if err := s.manager.DetachAll(ctx); err != nil {
		return fmt.Errorf("failed to detach programs: %w", err)
	}

	logger.Info("eBPF monitoring system stopped")
	return nil
}

// IsRunning returns true if the system is active.
func (s *System) IsRunning() bool {
	return s.manager.IsRunning()
}

// GetPrograms returns status of all programs.
func (s *System) GetPrograms() []core.ProgramStatus {
	return s.manager.GetProgramStatus()
}

// QueryEvents retrieves events matching the criteria.
func (s *System) QueryEvents(ctx context.Context, query core.Query) ([]core.Event, error) {
	return s.storage.Query(ctx, query)
}

// CountEvents returns the number of events matching the criteria.
func (s *System) CountEvents(ctx context.Context, query core.Query) (int, error) {
	return s.storage.Count(ctx, query)
}
