package bpf

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkEventStorage(b *testing.B) {
	storage := NewInMemoryStorage()

	b.Run("Store events", func(b *testing.B) {
		events := make([]*MockEvent, b.N)
		for i := 0; i < b.N; i++ {
			events[i] = &MockEvent{
				BaseEvent: BaseEvent{
					PID: uint32(i % 100), // Spread across 100 PIDs
					TS:  uint64(time.Now().UnixNano()),
				},
				eventType: fmt.Sprintf("type_%d", i%5), // 5 different event types
			}
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			storage.Store(events[i])
		}
	})

	// Pre-populate storage for read benchmarks
	for i := 0; i < 1000; i++ {
		event := &MockEvent{
			BaseEvent: BaseEvent{
				PID: uint32(i % 100),
				TS:  uint64(time.Now().UnixNano()),
				Comm: [16]byte{
					byte('t'), byte('e'), byte('s'), byte('t'),
					byte('0' + (i/100)%10), byte('0' + (i/10)%10), byte('0' + i%10),
				},
			},
			eventType: fmt.Sprintf("type_%d", i%5),
		}
		storage.Store(event)
	}

	b.Run("Count by PID", func(b *testing.B) {
		since := time.Now().Add(-1 * time.Hour)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			storage.Count(uint32(i%100), "", "", since)
		}
	})

	b.Run("Count by command", func(b *testing.B) {
		since := time.Now().Add(-1 * time.Hour)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			storage.Count(0, "test", "", since)
		}
	})

	b.Run("Count by type", func(b *testing.B) {
		since := time.Now().Add(-1 * time.Hour)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			storage.Count(0, "", fmt.Sprintf("type_%d", i%5), since)
		}
	})

	b.Run("GetByPID", func(b *testing.B) {
		since := time.Now().Add(-1 * time.Hour)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			storage.GetByPID(uint32(i%100), since)
		}
	})

	b.Run("GetByType", func(b *testing.B) {
		since := time.Now().Add(-1 * time.Hour)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			storage.GetByType(fmt.Sprintf("type_%d", i%5), since)
		}
	})

	b.Run("Cleanup", func(b *testing.B) {
		// Add events to clean up
		for i := 0; i < 100; i++ {
			oldEvent := &MockEvent{
				BaseEvent: BaseEvent{
					PID: uint32(i),
					TS:  uint64(time.Now().Add(-2*time.Hour).UnixNano()),
				},
				eventType: "cleanup_test",
			}
			storage.Store(oldEvent)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			storage.Cleanup(1 * time.Hour)
		}
	})
}

func BenchmarkManager(b *testing.B) {
	b.Run("Program registration", func(b *testing.B) {
		manager := NewManager()
		programs := make([]*MockProgram, b.N)
		
		for i := 0; i < b.N; i++ {
			programs[i] = NewMockProgram(
				fmt.Sprintf("program_%d", i),
				fmt.Sprintf("Program %d", i),
				manager.GetStorage(),
			)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			manager.RegisterProgram(programs[i])
		}
	})

	b.Run("Event aggregation", func(b *testing.B) {
		manager := NewManager()
		program := NewMockProgram("bench", "Benchmark program", manager.GetStorage())
		
		manager.RegisterProgram(program)
		manager.LoadAll()
		manager.AttachAll()
		manager.StartAll()

		events := make([]*MockEvent, b.N)
		for i := 0; i < b.N; i++ {
			events[i] = &MockEvent{
				BaseEvent: BaseEvent{
					PID: uint32(i),
					TS:  uint64(time.Now().UnixNano()),
				},
				eventType: "bench",
			}
		}

		// Start goroutine to consume aggregated events
		done := make(chan bool)
		go func() {
			aggregatedChan := manager.GetAggregatedEvents()
			count := 0
			for range aggregatedChan {
				count++
				if count >= b.N {
					break
				}
			}
			done <- true
		}()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			program.SendEvent(events[i])
		}

		// Wait for all events to be processed
		<-done
		manager.StopAll()
	})
}

func BenchmarkEventProcessing(b *testing.B) {
	b.Run("BaseEvent methods", func(b *testing.B) {
		event := &MockEvent{
			BaseEvent: BaseEvent{
				PID:  1234,
				TS:   uint64(time.Now().UnixNano()),
				Comm: [16]byte{'t', 'e', 's', 't', 'c', 'm', 'd', 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			eventType: "benchmark",
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = event.GetPID()
			_ = event.GetTimestamp()
			_ = event.GetCommand()
			_ = event.GetWallClockTime()
			_ = event.GetEventType()
		}
	})
}

// Benchmark memory usage
func BenchmarkMemoryUsage(b *testing.B) {
	b.Run("Storage growth", func(b *testing.B) {
		storage := NewInMemoryStorage()
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			event := &MockEvent{
				BaseEvent: BaseEvent{
					PID: uint32(i % 1000), // Limit to 1000 PIDs
					TS:  uint64(time.Now().UnixNano()),
				},
				eventType: fmt.Sprintf("type_%d", i%10), // 10 types
			}
			storage.Store(event)
			
			// Periodic cleanup to prevent unlimited growth
			if i%10000 == 0 {
				storage.Cleanup(10 * time.Minute)
			}
		}
	})
}

// Test concurrent access performance
func BenchmarkConcurrentAccess(b *testing.B) {
	storage := NewInMemoryStorage()
	
	// Pre-populate storage
	for i := 0; i < 1000; i++ {
		event := &MockEvent{
			BaseEvent: BaseEvent{
				PID: uint32(i % 100),
				TS:  uint64(time.Now().UnixNano()),
			},
			eventType: fmt.Sprintf("type_%d", i%5),
		}
		storage.Store(event)
	}

	b.Run("Concurrent reads", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			since := time.Now().Add(-1 * time.Hour)
			for pb.Next() {
				storage.Count(uint32(i%100), "", "", since)
				i++
			}
		})
	})

	b.Run("Concurrent writes", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				event := &MockEvent{
					BaseEvent: BaseEvent{
						PID: uint32(i % 100),
						TS:  uint64(time.Now().UnixNano()),
					},
					eventType: "concurrent",
				}
				storage.Store(event)
				i++
			}
		})
	})

	b.Run("Mixed read/write", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			since := time.Now().Add(-1 * time.Hour)
			for pb.Next() {
				if i%2 == 0 {
					// Read operation
					storage.Count(uint32(i%100), "", "", since)
				} else {
					// Write operation
					event := &MockEvent{
						BaseEvent: BaseEvent{
							PID: uint32(i % 100),
							TS:  uint64(time.Now().UnixNano()),
						},
						eventType: "mixed",
					}
					storage.Store(event)
				}
				i++
			}
		})
	})
}
