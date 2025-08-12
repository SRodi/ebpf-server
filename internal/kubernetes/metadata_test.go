package kubernetes

import (
	"os"
	"testing"
)

func TestKubernetesProvider(t *testing.T) {
	// Save original env vars
	originalHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	originalMode := os.Getenv("DEPLOYMENT_MODE")
	originalNodeName := os.Getenv("NODE_NAME")
	originalPodName := os.Getenv("POD_NAME")
	originalNamespace := os.Getenv("POD_NAMESPACE")

	// Cleanup function
	defer func() {
		os.Setenv("KUBERNETES_SERVICE_HOST", originalHost)
		os.Setenv("DEPLOYMENT_MODE", originalMode)
		os.Setenv("NODE_NAME", originalNodeName)
		os.Setenv("POD_NAME", originalPodName)
		os.Setenv("POD_NAMESPACE", originalNamespace)
	}()

	t.Run("VM environment", func(t *testing.T) {
		// Clear all Kubernetes env vars
		os.Unsetenv("KUBERNETES_SERVICE_HOST")
		os.Unsetenv("DEPLOYMENT_MODE")
		os.Unsetenv("NODE_NAME")
		os.Unsetenv("POD_NAME")
		os.Unsetenv("POD_NAMESPACE")

		provider := NewProvider()
		if provider.IsEnabled() {
			t.Error("Provider should not be enabled in VM environment")
		}

		metadata := provider.GetMetadata()
		if metadata != nil {
			t.Error("Metadata should be nil in VM environment")
		}
	})

	t.Run("Kubernetes environment with deployment mode", func(t *testing.T) {
		os.Setenv("DEPLOYMENT_MODE", "kubernetes")
		os.Setenv("NODE_NAME", "test-node-1")
		os.Setenv("POD_NAME", "ebpf-monitor-12345")
		os.Setenv("POD_NAMESPACE", "ebpf-system")

		provider := NewProvider()
		if !provider.IsEnabled() {
			t.Error("Provider should be enabled in Kubernetes environment")
		}

		metadata := provider.GetMetadata()
		if metadata == nil {
			t.Fatal("Metadata should not be nil in Kubernetes environment")
		}

		if metadata.NodeName != "test-node-1" {
			t.Errorf("Expected node name 'test-node-1', got '%s'", metadata.NodeName)
		}

		if metadata.PodName != "ebpf-monitor-12345" {
			t.Errorf("Expected pod name 'ebpf-monitor-12345', got '%s'", metadata.PodName)
		}

		if metadata.Namespace != "ebpf-system" {
			t.Errorf("Expected namespace 'ebpf-system', got '%s'", metadata.Namespace)
		}
	})

	t.Run("Kubernetes environment with service host", func(t *testing.T) {
		os.Unsetenv("DEPLOYMENT_MODE")
		os.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
		os.Setenv("NODE_NAME", "test-node-2")

		provider := NewProvider()
		if !provider.IsEnabled() {
			t.Error("Provider should be enabled when KUBERNETES_SERVICE_HOST is set")
		}
	})

	t.Run("AddToMap functionality", func(t *testing.T) {
		os.Setenv("DEPLOYMENT_MODE", "kubernetes")
		os.Setenv("NODE_NAME", "test-node")
		os.Setenv("POD_NAME", "test-pod")
		os.Setenv("POD_NAMESPACE", "test-ns")

		provider := NewProvider()
		data := make(map[string]interface{})
		
		provider.AddToMap(data)

		if data["k8s_node_name"] != "test-node" {
			t.Errorf("Expected k8s_node_name 'test-node', got '%v'", data["k8s_node_name"])
		}

		if data["k8s_pod_name"] != "test-pod" {
			t.Errorf("Expected k8s_pod_name 'test-pod', got '%v'", data["k8s_pod_name"])
		}

		if data["k8s_namespace"] != "test-ns" {
			t.Errorf("Expected k8s_namespace 'test-ns', got '%v'", data["k8s_namespace"])
		}
	})
}
