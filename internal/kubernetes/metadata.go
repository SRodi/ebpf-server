// Package kubernetes provides Kubernetes-specific metadata and utilities.
package kubernetes

import (
	"os"
	"sync"
)

// Metadata represents Kubernetes-specific metadata for events.
type Metadata struct {
	NodeName  string `json:"node_name,omitempty"`
	PodName   string `json:"pod_name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// Provider provides Kubernetes metadata for events.
type Provider struct {
	metadata *Metadata
	mu       sync.RWMutex
	enabled  bool
}

// NewProvider creates a new Kubernetes metadata provider.
func NewProvider() *Provider {
	p := &Provider{
		enabled: isKubernetesEnvironment(),
	}

	if p.enabled {
		p.metadata = &Metadata{
			NodeName:  os.Getenv("NODE_NAME"),
			PodName:   os.Getenv("POD_NAME"),
			Namespace: os.Getenv("POD_NAMESPACE"),
		}
	}

	return p
}

// IsEnabled returns true if running in Kubernetes environment.
func (p *Provider) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

// GetMetadata returns the Kubernetes metadata.
func (p *Provider) GetMetadata() *Metadata {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.enabled || p.metadata == nil {
		return nil
	}

	// Return a copy to avoid race conditions
	return &Metadata{
		NodeName:  p.metadata.NodeName,
		PodName:   p.metadata.PodName,
		Namespace: p.metadata.Namespace,
	}
}

// AddToMap adds Kubernetes metadata to a map.
func (p *Provider) AddToMap(data map[string]interface{}) {
	if !p.IsEnabled() {
		return
	}

	metadata := p.GetMetadata()
	if metadata == nil {
		return
	}

	if metadata.NodeName != "" {
		data["k8s_node_name"] = metadata.NodeName
	}
	if metadata.PodName != "" {
		data["k8s_pod_name"] = metadata.PodName
	}
	if metadata.Namespace != "" {
		data["k8s_namespace"] = metadata.Namespace
	}
}

// isKubernetesEnvironment checks if we're running in Kubernetes.
func isKubernetesEnvironment() bool {
	// Check for standard Kubernetes environment variables
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}

	// Check deployment mode environment variable
	if os.Getenv("DEPLOYMENT_MODE") == "kubernetes" {
		return true
	}

	// Check if we can find Kubernetes service account token
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}

	return false
}
