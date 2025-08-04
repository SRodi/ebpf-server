package bpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// Global manager instance
var globalManager *Manager

// connectionEventWrapper wraps the legacy Event type to implement BPFEvent
type connectionEventWrapper struct {
	Event
}

func (e *connectionEventWrapper) GetEventType() string {
	return "connection"
}

func (e *connectionEventWrapper) GetPID() uint32 {
	return e.Event.PID
}

func (e *connectionEventWrapper) GetTimestamp() uint64 {
	return e.Event.TS
}

func (e *connectionEventWrapper) GetWallClockTime() time.Time {
	bootTime := GetSystemBootTime()
	return bootTime.Add(time.Duration(e.Event.TS))
}

// packetDropEventWrapper wraps the legacy DropEvent type to implement BPFEvent
type packetDropEventWrapper struct {
	DropEvent
}

func (e *packetDropEventWrapper) GetEventType() string {
	return "packet_drop"
}

func (e *packetDropEventWrapper) GetPID() uint32 {
	return e.DropEvent.PID
}

func (e *packetDropEventWrapper) GetTimestamp() uint64 {
	return e.DropEvent.TS
}

func (e *packetDropEventWrapper) GetWallClockTime() time.Time {
	bootTime := GetSystemBootTime()
	return bootTime.Add(time.Duration(e.DropEvent.TS))
}

// connectionProgramWrapper wraps the legacy program for testing
type connectionProgramWrapper struct {
	storage EventStorage
}

func (p *connectionProgramWrapper) GetName() string {
	return "connection"
}

func (p *connectionProgramWrapper) GetDescription() string {
	return "Mock connection monitoring program for testing"
}

func (p *connectionProgramWrapper) GetObjectPath() string {
	return "bpf/connection.o"
}

func (p *connectionProgramWrapper) Load() error {
	return fmt.Errorf("mock program cannot load")
}

func (p *connectionProgramWrapper) Attach() error {
	return fmt.Errorf("mock program cannot attach")
}

func (p *connectionProgramWrapper) Start(ctx context.Context) error {
	return fmt.Errorf("mock program cannot start")
}

func (p *connectionProgramWrapper) Stop() error {
	return nil
}

func (p *connectionProgramWrapper) IsRunning() bool {
	return false
}

func (p *connectionProgramWrapper) GetEventChannel() <-chan BPFEvent {
	return make(<-chan BPFEvent)
}

func (p *connectionProgramWrapper) GetSummary(pid uint32, command string, durationSeconds int) int {
	since := GetSystemBootTime().Add(-time.Duration(durationSeconds) * time.Second)
	return p.storage.Count(pid, command, "connection", since)
}

func (p *connectionProgramWrapper) GetAllEvents() map[uint32][]BPFEvent {
	allEvents := p.storage.GetAll()
	if connectionEvents, exists := allEvents["connection"]; exists {
		return connectionEvents
	}
	return make(map[uint32][]BPFEvent)
}

// packetDropProgramWrapper wraps the legacy program for testing
type packetDropProgramWrapper struct {
	storage EventStorage
}

func (p *packetDropProgramWrapper) GetName() string {
	return "packet_drop"
}

func (p *packetDropProgramWrapper) GetDescription() string {
	return "Mock packet drop monitoring program for testing"
}

func (p *packetDropProgramWrapper) GetObjectPath() string {
	return "bpf/packet_drop.o"
}

func (p *packetDropProgramWrapper) Load() error {
	return fmt.Errorf("mock program cannot load")
}

func (p *packetDropProgramWrapper) Attach() error {
	return fmt.Errorf("mock program cannot attach")
}

func (p *packetDropProgramWrapper) Start(ctx context.Context) error {
	return fmt.Errorf("mock program cannot start")
}

func (p *packetDropProgramWrapper) Stop() error {
	return nil
}

func (p *packetDropProgramWrapper) IsRunning() bool {
	return false
}

func (p *packetDropProgramWrapper) GetEventChannel() <-chan BPFEvent {
	return make(<-chan BPFEvent)
}

func (p *packetDropProgramWrapper) GetSummary(pid uint32, command string, durationSeconds int) int {
	since := GetSystemBootTime().Add(-time.Duration(durationSeconds) * time.Second)
	return p.storage.Count(pid, command, "packet_drop", since)
}

func (p *packetDropProgramWrapper) GetAllEvents() map[uint32][]BPFEvent {
	allEvents := p.storage.GetAll()
	if dropEvents, exists := allEvents["packet_drop"]; exists {
		return dropEvents
	}
	return make(map[uint32][]BPFEvent)
}

// connectionProgram implements BPFProgram for connection monitoring
type connectionProgram struct {
	name        string
	description string
	objectPath  string
	
	// eBPF resources
	collection *ebpf.Collection
	eventsMap  *ebpf.Map
	links      []link.Link
	reader     *ringbuf.Reader
	
	// Event processing
	eventChan chan BPFEvent
	ctx       context.Context
	cancel    context.CancelFunc
	running   bool
	
	// Storage
	storage EventStorage
}

func newConnectionProgram(storage EventStorage) *connectionProgram {
	return &connectionProgram{
		name:        "connection",
		description: "Monitors network connection attempts via sys_enter_connect tracepoint",
		objectPath:  "bpf/connection.o",
		eventChan:   make(chan BPFEvent, 1000),
		storage:     storage,
	}
}

func (p *connectionProgram) GetName() string {
	return p.name
}

func (p *connectionProgram) GetDescription() string {
	return p.description
}

func (p *connectionProgram) GetObjectPath() string {
	return p.objectPath
}

func (p *connectionProgram) Load() error {
	spec, err := ebpf.LoadCollectionSpec(p.objectPath)
	if err != nil {
		return fmt.Errorf("failed to load collection spec: %w", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}

	p.collection = collection
	p.eventsMap = collection.Maps["events"]

	logger.Infof("Connection monitoring program loaded from %s", p.objectPath)
	return nil
}

func (p *connectionProgram) Attach() error {
	if p.collection == nil {
		return fmt.Errorf("program not loaded")
	}

	prog := p.collection.Programs["trace_connect"]
	if prog == nil {
		return fmt.Errorf("trace_connect program not found in collection")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", prog, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint: %w", err)
	}

	p.links = append(p.links, tp)

	reader, err := ringbuf.NewReader(p.eventsMap)
	if err != nil {
		tp.Close()
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	p.reader = reader
	logger.Info("Connection monitoring program attached to sys_enter_connect tracepoint")
	return nil
}

func (p *connectionProgram) Start(ctx context.Context) error {
	if p.reader == nil {
		return fmt.Errorf("program not attached")
	}

	if p.running {
		return fmt.Errorf("program already running")
	}

	p.ctx, p.cancel = context.WithCancel(ctx)
	p.running = true

	go p.processEvents()

	logger.Info("Connection monitoring program started")
	return nil
}

func (p *connectionProgram) Stop() error {
	if !p.running {
		return nil
	}

	if p.cancel != nil {
		p.cancel()
	}

	if p.reader != nil {
		p.reader.Close()
		p.reader = nil
	}

	for _, l := range p.links {
		if l != nil {
			l.Close()
		}
	}
	p.links = nil

	if p.collection != nil {
		p.collection.Close()
		p.collection = nil
	}

	p.running = false
	close(p.eventChan)

	logger.Info("Connection monitoring program stopped")
	return nil
}

func (p *connectionProgram) IsRunning() bool {
	return p.running
}

func (p *connectionProgram) GetEventChannel() <-chan BPFEvent {
	return p.eventChan
}

func (p *connectionProgram) GetSummary(pid uint32, command string, durationSeconds int) int {
	since := GetSystemBootTime().Add(-time.Duration(durationSeconds) * time.Second)
	return p.storage.Count(pid, command, p.name, since)
}

func (p *connectionProgram) GetAllEvents() map[uint32][]BPFEvent {
	allEvents := p.storage.GetAll()
	if connectionEvents, exists := allEvents[p.name]; exists {
		return connectionEvents
	}
	return make(map[uint32][]BPFEvent)
}

func (p *connectionProgram) processEvents() {
	logger.Info("Starting connection event processing...")

	for {
		select {
		case <-p.ctx.Done():
			logger.Info("Stopping connection event processing...")
			return
		default:
			record, err := p.reader.Read()
			if err != nil {
				if p.ctx.Err() != nil {
					return
				}
				logger.Errorf("Error reading from connection ring buffer: %v", err)
				continue
			}

			if err := p.processEvent(record.RawSample); err != nil {
				logger.Errorf("Error processing connection event: %v", err)
			}
		}
	}
}

func (p *connectionProgram) processEvent(data []byte) error {
	if len(data) < 60 {
		return fmt.Errorf("connection event data too short: %d bytes", len(data))
	}

	var event Event

	// Parse according to the C struct layout
	event.PID = binary.LittleEndian.Uint32(data[0:4])
	event.TS = binary.LittleEndian.Uint64(data[4:12])
	event.Ret = int32(binary.LittleEndian.Uint32(data[12:16]))
	copy(event.Comm[:], data[16:32])
	event.DestIPv4 = binary.LittleEndian.Uint32(data[32:36])
	copy(event.DestIPv6[:], data[36:52])
	event.DestPort = binary.LittleEndian.Uint16(data[52:54])
	event.Family = binary.LittleEndian.Uint16(data[54:56])
	event.Protocol = data[56]
	event.SockType = data[57]

	// Handle address data based on family
	const AF_INET = 2
	const AF_INET6 = 10

	if event.Family == AF_INET6 {
		event.DestIPv4 = 0
	} else if event.Family == AF_INET {
		for i := range event.DestIPv6 {
			event.DestIPv6[i] = 0
		}
	}

	// Skip events with no valid destination
	if event.GetDestIP() == "" {
		return nil
	}

	// Wrap and store
	wrapper := &connectionEventWrapper{Event: event}
	if err := p.storage.Store(wrapper); err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	// Send to channel
	select {
	case p.eventChan <- wrapper:
	default:
		logger.Infof("Connection event channel full, dropping event")
	}

	logger.Debugf("Connection event: PID=%d, Command=%s, Dest=%s, Protocol=%s",
		event.PID, event.GetCommand(), event.GetDestination(), event.GetProtocol())

	return nil
}

// packetDropProgram implements BPFProgram for packet drop monitoring
type packetDropProgram struct {
	name        string
	description string
	objectPath  string
	
	// eBPF resources
	collection *ebpf.Collection
	eventsMap  *ebpf.Map
	links      []link.Link
	reader     *ringbuf.Reader
	
	// Event processing
	eventChan chan BPFEvent
	ctx       context.Context
	cancel    context.CancelFunc
	running   bool
	
	// Storage
	storage EventStorage
}

func newPacketDropProgram(storage EventStorage) *packetDropProgram {
	return &packetDropProgram{
		name:        "packet_drop",
		description: "Monitors packet drops via kfree_skb tracepoint and tcp_drop kprobe",
		objectPath:  "bpf/packet_drop.o",
		eventChan:   make(chan BPFEvent, 1000),
		storage:     storage,
	}
}

func (p *packetDropProgram) GetName() string {
	return p.name
}

func (p *packetDropProgram) GetDescription() string {
	return p.description
}

func (p *packetDropProgram) GetObjectPath() string {
	return p.objectPath
}

func (p *packetDropProgram) Load() error {
	spec, err := ebpf.LoadCollectionSpec(p.objectPath)
	if err != nil {
		return fmt.Errorf("failed to load collection spec: %w", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}

	p.collection = collection
	p.eventsMap = collection.Maps["drop_events"]

	logger.Infof("Packet drop monitoring program loaded from %s", p.objectPath)
	return nil
}

func (p *packetDropProgram) Attach() error {
	if p.collection == nil {
		return fmt.Errorf("program not loaded")
	}

	attachedCount := 0

	// Try to attach kfree_skb tracepoint
	if prog, exists := p.collection.Programs["trace_kfree_skb"]; exists {
		tp, err := link.Tracepoint("skb", "kfree_skb", prog, nil)
		if err != nil {
			logger.Infof("Could not attach kfree_skb tracepoint: %v", err)
		} else {
			p.links = append(p.links, tp)
			attachedCount++
			logger.Info("Attached kfree_skb tracepoint for packet drop monitoring")
		}
	}

	// Try to attach tcp_drop kprobe
	if prog, exists := p.collection.Programs["trace_tcp_drop"]; exists {
		kp, err := link.Kprobe("tcp_drop", prog, nil)
		if err != nil {
			logger.Infof("Could not attach tcp_drop kprobe: %v", err)
		} else {
			p.links = append(p.links, kp)
			attachedCount++
			logger.Info("Attached tcp_drop kprobe for packet drop monitoring")
		}
	}

	if attachedCount == 0 {
		return fmt.Errorf("no packet drop attach points available")
	}

	reader, err := ringbuf.NewReader(p.eventsMap)
	if err != nil {
		for _, l := range p.links {
			l.Close()
		}
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	p.reader = reader
	logger.Infof("Packet drop monitoring program attached (%d attach points)", attachedCount)
	return nil
}

func (p *packetDropProgram) Start(ctx context.Context) error {
	if p.reader == nil {
		return fmt.Errorf("program not attached")
	}

	if p.running {
		return fmt.Errorf("program already running")
	}

	p.ctx, p.cancel = context.WithCancel(ctx)
	p.running = true

	go p.processEvents()

	logger.Info("Packet drop monitoring program started")
	return nil
}

func (p *packetDropProgram) Stop() error {
	if !p.running {
		return nil
	}

	if p.cancel != nil {
		p.cancel()
	}

	if p.reader != nil {
		p.reader.Close()
		p.reader = nil
	}

	for _, l := range p.links {
		if l != nil {
			l.Close()
		}
	}
	p.links = nil

	if p.collection != nil {
		p.collection.Close()
		p.collection = nil
	}

	p.running = false
	close(p.eventChan)

	logger.Info("Packet drop monitoring program stopped")
	return nil
}

func (p *packetDropProgram) IsRunning() bool {
	return p.running
}

func (p *packetDropProgram) GetEventChannel() <-chan BPFEvent {
	return p.eventChan
}

func (p *packetDropProgram) GetSummary(pid uint32, command string, durationSeconds int) int {
	since := GetSystemBootTime().Add(-time.Duration(durationSeconds) * time.Second)
	return p.storage.Count(pid, command, p.name, since)
}

func (p *packetDropProgram) GetAllEvents() map[uint32][]BPFEvent {
	allEvents := p.storage.GetAll()
	if dropEvents, exists := allEvents[p.name]; exists {
		return dropEvents
	}
	return make(map[uint32][]BPFEvent)
}

func (p *packetDropProgram) processEvents() {
	logger.Info("Starting packet drop event processing...")

	for {
		select {
		case <-p.ctx.Done():
			logger.Info("Stopping packet drop event processing...")
			return
		default:
			record, err := p.reader.Read()
			if err != nil {
				if p.ctx.Err() != nil {
					return
				}
				logger.Errorf("Error reading from packet drop ring buffer: %v", err)
				continue
			}

			if err := p.processEvent(record.RawSample); err != nil {
				logger.Errorf("Error processing packet drop event: %v", err)
			}
		}
	}
}

func (p *packetDropProgram) processEvent(data []byte) error {
	if len(data) < 32 {
		return fmt.Errorf("drop event data too short: %d bytes", len(data))
	}

	var event DropEvent

	// Parse according to the C struct layout
	event.PID = binary.LittleEndian.Uint32(data[0:4])
	event.TS = binary.LittleEndian.Uint64(data[4:12])
	copy(event.Comm[:], data[12:28])
	event.DropReason = binary.LittleEndian.Uint32(data[28:32])
	if len(data) >= 36 {
		event.SkbLen = binary.LittleEndian.Uint32(data[32:36])
	}

	// Wrap and store
	wrapper := &packetDropEventWrapper{DropEvent: event}
	if err := p.storage.Store(wrapper); err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	// Send to channel
	select {
	case p.eventChan <- wrapper:
	default:
		logger.Infof("Packet drop event channel full, dropping event")
	}

	logger.Debugf("Packet drop event: PID=%d, Command=%s, Reason=%s, WallTime=%s",
		event.PID, event.GetCommand(), event.GetDropReasonString(),
		wrapper.GetWallClockTime().Format("2006-01-02 15:04:05"))

	return nil
}

// registerDefaultPrograms registers all default eBPF programs
func registerDefaultPrograms() error {
	storage := globalManager.GetStorage()

	// Register connection monitoring program
	connectionProg := newConnectionProgram(storage)
	if err := globalManager.RegisterProgram(connectionProg); err != nil {
		return fmt.Errorf("failed to register connection program: %w", err)
	}

	// Register packet drop monitoring program
	packetDropProg := newPacketDropProgram(storage)
	if err := globalManager.RegisterProgram(packetDropProg); err != nil {
		return fmt.Errorf("failed to register packet drop program: %w", err)
	}

	logger.Info("Registered all default eBPF programs")
	return nil
}

// LoadAndAttach initializes and starts all eBPF programs using the new modular architecture
func LoadAndAttach() error {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// Create manager and storage
	globalManager = NewManager()

	// Check if eBPF is available
	if !globalManager.IsAvailable() {
		logger.Info("eBPF not available, running without monitoring")
		return nil
	}

	// Register all default programs
	if err := registerDefaultPrograms(); err != nil {
		return err
	}

	// Load all programs
	if err := globalManager.LoadAll(); err != nil {
		return err
	}

	// Attach all programs
	if err := globalManager.AttachAll(); err != nil {
		return err
	}

	// Start all programs
	if err := globalManager.StartAll(); err != nil {
		return err
	}

	logger.Info("eBPF programs loaded and started successfully")
	return nil
}

// Cleanup stops all programs and cleans up resources
func Cleanup() {
	if globalManager != nil {
		if err := globalManager.StopAll(); err != nil {
			logger.Error("Failed to stop eBPF programs", "error", err)
		}
		logger.Info("eBPF cleanup complete")
	}
}

// GetConnectionSummary returns connection statistics - maintains backward compatibility
func GetConnectionSummary(pid uint32, command string, durationSeconds int) int {
	if globalManager == nil {
		return 0
	}

	if program, exists := globalManager.GetProgram("connection"); exists {
		return program.GetSummary(pid, command, durationSeconds)
	}
	return 0
}

// GetPacketDropSummary returns packet drop statistics - maintains backward compatibility
func GetPacketDropSummary(pid uint32, command string, durationSeconds int) int {
	if globalManager == nil {
		return 0
	}

	if program, exists := globalManager.GetProgram("packet_drop"); exists {
		return program.GetSummary(pid, command, durationSeconds)
	}
	return 0
}

// GetAllConnections returns all connection events - maintains backward compatibility
func GetAllConnections() map[uint32][]Event {
	if globalManager == nil {
		return make(map[uint32][]Event)
	}

	// Get connection events from storage
	storage := globalManager.GetStorage()
	allEvents := storage.GetAll()
	
	if connectionEvents, exists := allEvents["connection"]; exists {
		// Convert BPFEvent back to Event for backward compatibility
		result := make(map[uint32][]Event)
		for pid, events := range connectionEvents {
			for _, event := range events {
				if connEvent, ok := event.(*connectionEventWrapper); ok {
					result[pid] = append(result[pid], connEvent.Event)
				}
			}
		}
		return result
	}
	
	return make(map[uint32][]Event)
}

// GetAllPacketDrops returns all packet drop events - maintains backward compatibility  
func GetAllPacketDrops() map[uint32][]DropEvent {
	if globalManager == nil {
		return make(map[uint32][]DropEvent)
	}

	// Get packet drop events from storage
	storage := globalManager.GetStorage()
	allEvents := storage.GetAll()
	
	if dropEvents, exists := allEvents["packet_drop"]; exists {
		// Convert BPFEvent back to DropEvent for backward compatibility
		result := make(map[uint32][]DropEvent)
		for pid, events := range dropEvents {
			for _, event := range events {
				if dropEvent, ok := event.(*packetDropEventWrapper); ok {
					result[pid] = append(result[pid], dropEvent.DropEvent)
				}
			}
		}
		return result
	}
	
	return make(map[uint32][]DropEvent)
}

// IsAvailable checks if eBPF is available - maintains backward compatibility
func IsAvailable() bool {
	if globalManager == nil {
		manager := NewManager()
		return manager.IsAvailable()
	}
	return globalManager.IsAvailable()
}

// GetManager returns the global manager for advanced usage
func GetManager() *Manager {
	return globalManager
}
