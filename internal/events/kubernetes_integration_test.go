package events

import (
	"os"
	"sync"
	"testing"
	"time"
)

func TestKubernetesMetadataIntegration(t *testing.T) {
	// Save original env vars
	originalMode := os.Getenv("DEPLOYMENT_MODE")
	originalNodeName := os.Getenv("NODE_NAME")
	originalPodName := os.Getenv("POD_NAME")
	originalNamespace := os.Getenv("POD_NAMESPACE")

	// Cleanup function
	defer func() {
		os.Setenv("DEPLOYMENT_MODE", originalMode)
		os.Setenv("NODE_NAME", originalNodeName)
		os.Setenv("POD_NAME", originalPodName)
		os.Setenv("POD_NAMESPACE", originalNamespace)
		// Reset the provider for future tests
		k8sProvider = nil
		k8sOnce = sync.Once{}
	}()

	t.Run("VM mode - no Kubernetes metadata", func(t *testing.T) {
		// Clear all Kubernetes env vars
		os.Unsetenv("DEPLOYMENT_MODE")
		os.Unsetenv("NODE_NAME")
		os.Unsetenv("POD_NAME")
		os.Unsetenv("POD_NAMESPACE")
		
		// Reset provider
		k8sProvider = nil
		k8sOnce = sync.Once{}

		metadata := map[string]interface{}{
			"custom_field": "test_value",
		}

		event := NewBaseEvent("test", 1234, "test-cmd", uint64(time.Now().UnixNano()), metadata)

		// Should not have Kubernetes metadata
		eventMetadata := event.Metadata()
		if _, exists := eventMetadata["k8s_node_name"]; exists {
			t.Error("Event should not have k8s_node_name in VM mode")
		}
		if _, exists := eventMetadata["k8s_pod_name"]; exists {
			t.Error("Event should not have k8s_pod_name in VM mode")
		}
		if _, exists := eventMetadata["k8s_namespace"]; exists {
			t.Error("Event should not have k8s_namespace in VM mode")
		}

		// Should still have custom metadata
		if eventMetadata["custom_field"] != "test_value" {
			t.Error("Custom metadata should be preserved")
		}
	})

	t.Run("Kubernetes mode - with metadata", func(t *testing.T) {
		// Set Kubernetes environment
		os.Setenv("DEPLOYMENT_MODE", "kubernetes")
		os.Setenv("NODE_NAME", "test-node-1")
		os.Setenv("POD_NAME", "ebpf-monitor-abcde")
		os.Setenv("POD_NAMESPACE", "ebpf-system")
		
		// Reset provider to pick up new env vars
		k8sProvider = nil
		k8sOnce = sync.Once{}

		metadata := map[string]interface{}{
			"custom_field": "test_value",
		}

		event := NewBaseEvent("connection", 5678, "curl", uint64(time.Now().UnixNano()), metadata)

		// Should have Kubernetes metadata
		eventMetadata := event.Metadata()
		if eventMetadata["k8s_node_name"] != "test-node-1" {
			t.Errorf("Expected k8s_node_name 'test-node-1', got '%v'", eventMetadata["k8s_node_name"])
		}
		if eventMetadata["k8s_pod_name"] != "ebpf-monitor-abcde" {
			t.Errorf("Expected k8s_pod_name 'ebpf-monitor-abcde', got '%v'", eventMetadata["k8s_pod_name"])
		}
		if eventMetadata["k8s_namespace"] != "ebpf-system" {
			t.Errorf("Expected k8s_namespace 'ebpf-system', got '%v'", eventMetadata["k8s_namespace"])
		}

		// Should still have custom metadata
		if eventMetadata["custom_field"] != "test_value" {
			t.Error("Custom metadata should be preserved")
		}

		// Verify basic event properties
		if event.Type() != "connection" {
			t.Errorf("Expected event type 'connection', got '%s'", event.Type())
		}
		if event.PID() != 5678 {
			t.Errorf("Expected PID 5678, got %d", event.PID())
		}
		if event.Command() != "curl" {
			t.Errorf("Expected command 'curl', got '%s'", event.Command())
		}
	})
}
