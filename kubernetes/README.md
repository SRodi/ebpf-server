# eBPF Monitor - Kubernetes Deployment Guide

This guide explains how to deploy the eBPF monitoring system in Kubernetes alongside the existing VM deployment option.

## Architecture Overview

The Kubernetes deployment consists of two main components:

1. **eBPF Monitor Agent (DaemonSet)**: Runs on every node to collect eBPF events with Kubernetes metadata
2. **eBPF Aggregator (Deployment)**: Centralized service that collects and aggregates events from all agents

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │    Node 1   │  │    Node 2   │  │        Node N       │  │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │   ┌─────────┐       │  │
│  │ │ eBPF    │ │  │ │ eBPF    │ │  │   │ eBPF    │       │  │
│  │ │ Agent   │ │  │ │ Agent   │ │  │   │ Agent   │       │  │
│  │ └────┬────┘ │  │ └────┬────┘ │  │   └────┬────┘       │  │
│  └──────┼──────┘  └──────┼──────┘  └────────┼────────────┘  │
│         │                │                  │                │
│         └────────────────┼──────────────────┘                │
│                          │                                   │
│                    ┌─────▼─────┐                             │
│                    │   eBPF    │                             │
│                    │ Aggregator│                             │
│                    │           │                             │
│                    └───────────┘                             │
└─────────────────────────────────────────────────────────────┘
```

## Features

- **Dual Deployment**: Works both on VMs (unchanged) and Kubernetes
- **Kubernetes Metadata**: Events include node name, pod name, and namespace
- **DaemonSet Architecture**: Ensures monitoring on every cluster node
- **Centralized Aggregation**: Single API endpoint for all cluster events
- **Backward Compatible**: Existing VM deployments continue to work unchanged

## Quick Start

### Prerequisites

- Kubernetes cluster (1.20+)
- `kubectl` configured for your cluster
- Docker registry access (or use local registry)
- `make` and `docker` installed

### Option 1: Using the Deployment Script (Recommended)

```bash
# Build, push, and deploy everything
./scripts/deploy.sh all --registry your-registry.com --tag v1.0.0

# Or step by step:
./scripts/deploy.sh build
./scripts/deploy.sh push --registry your-registry.com
./scripts/deploy.sh deploy
```

### Option 2: Using Make Targets

```bash
# Build Docker images
make docker-build

# Push to registry (update REGISTRY variable)
make docker-push REGISTRY=your-registry.com TAG=v1.0.0

# Deploy to Kubernetes
make k8s-deploy
```

### Option 3: Manual kubectl

```bash
# Apply manifests in order
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/rbac.yaml
kubectl apply -f kubernetes/configmap.yaml
kubectl apply -f kubernetes/services.yaml
kubectl apply -f kubernetes/aggregator-deployment.yaml
kubectl apply -f kubernetes/daemonset.yaml
```

## Configuration

### Environment Variables

The system detects Kubernetes environment automatically but can be controlled with:

| Variable | Description | Default |
|----------|-------------|---------|
| `DEPLOYMENT_MODE` | Set to "kubernetes" to force K8s mode | Auto-detected |
| `NODE_NAME` | Kubernetes node name | From downward API |
| `POD_NAME` | Pod name | From downward API |
| `POD_NAMESPACE` | Pod namespace | From downward API |
| `AGGREGATOR_URL` | Aggregator service URL | Auto-configured |

### Resource Limits

Default resource limits per pod:

**Agent (per node):**
- CPU: 100m request, 500m limit
- Memory: 128Mi request, 512Mi limit

**Aggregator:**
- CPU: 200m request, 1000m limit
- Memory: 256Mi request, 1Gi limit

Adjust in the manifest files as needed for your cluster size.

## API Access

### Aggregator API

The aggregator provides a unified API for all cluster events:

```bash
# Port-forward to access aggregator
kubectl port-forward -n ebpf-system svc/ebpf-aggregator 8081:8081

# Query all events
curl http://localhost:8081/api/events

# Query by type
curl http://localhost:8081/api/events?type=connection

# Query by node
curl 'http://localhost:8081/api/events' | jq '.events[] | select(.k8s_node_name=="node1")'

# Get aggregation stats
curl http://localhost:8081/api/stats
```

### Individual Agent APIs

Each agent also exposes its local API:

```bash
# List all agent pods
kubectl get pods -n ebpf-system -l app=ebpf-monitor

# Port-forward to specific agent
kubectl port-forward -n ebpf-system ebpf-monitor-xxxxx 8080:8080

# Query local events
curl http://localhost:8080/api/events
```

## Event Format with Kubernetes Metadata

Events in Kubernetes mode include additional metadata:

```json
{
  "id": "1a2b3c4d5e6f7890",
  "type": "connection",
  "pid": 1234,
  "command": "curl",
  "timestamp": 1703764800000000000,
  "time": "2023-12-28T12:00:00.000000000Z",
  "k8s_node_name": "worker-node-1",
  "k8s_pod_name": "ebpf-monitor-abcde",
  "k8s_namespace": "ebpf-system",
  "source_ip": "10.244.1.5",
  "dest_ip": "142.250.191.14",
  "dest_port": 443
}
```

## Monitoring and Troubleshooting

### Check Deployment Status

```bash
# Quick status check
./scripts/deploy.sh status

# Or manually:
kubectl get pods -n ebpf-system
kubectl get daemonset -n ebpf-system
kubectl get deployment -n ebpf-system
```

### View Logs

```bash
# Aggregator logs
kubectl logs -l app=ebpf-aggregator -n ebpf-system -f

# Agent logs from all nodes
kubectl logs -l app=ebpf-monitor -n ebpf-system --tail=50

# Specific agent logs
kubectl logs -n ebpf-system ebpf-monitor-xxxxx -f
```

### Common Issues

**1. Agents not starting:**
- Check if nodes have required kernel headers: `kubectl describe pod -n ebpf-system`
- Verify privileged security context is allowed

**2. No events from agents:**
- Check eBPF program loading: `kubectl logs -n ebpf-system ebpf-monitor-xxxxx`
- Verify kernel version compatibility (4.18+ required)

**3. Aggregator connection issues:**
- Check service DNS resolution: `kubectl exec -n ebpf-system deploy/ebpf-aggregator -- nslookup ebpf-aggregator`
- Verify network policies don't block communication

## Scaling Considerations

### Large Clusters (100+ nodes)

1. **Increase aggregator resources:**
   ```yaml
   resources:
     requests:
       cpu: 500m
       memory: 1Gi
     limits:
       cpu: 2000m
       memory: 4Gi
   ```

2. **Configure event batching** (environment variables in daemonset):
   ```yaml
   - name: BATCH_SIZE
     value: "100"
   - name: FLUSH_INTERVAL
     value: "30s"
   ```

3. **Consider multiple aggregator replicas** for high availability:
   ```yaml
   spec:
     replicas: 2  # Add load balancer configuration
   ```

## VM Compatibility

The system maintains full backward compatibility with VM deployments:

```bash
# VM deployment (unchanged)
make build
sudo ./bin/ebpf-server

# Events in VM mode (no Kubernetes metadata):
{
  "id": "1a2b3c4d5e6f7890",
  "type": "connection",
  "pid": 1234,
  "command": "curl",
  "timestamp": 1703764800000000000,
  "time": "2023-12-28T12:00:00.000000000Z",
  "source_ip": "192.168.1.100",
  "dest_ip": "142.250.191.14",
  "dest_port": 443
}
```

## Cleanup

```bash
# Remove everything
./scripts/deploy.sh undeploy

# Or manually:
make k8s-undeploy
```

## Security Considerations

- Agents run with privileged security context (required for eBPF)
- RBAC limits permissions to necessary resources only
- Network policies can be added to restrict aggregator access
- Consider Pod Security Standards in restricted environments

## Performance

Expected overhead per node:
- CPU: ~50-100m under normal load
- Memory: ~100-200Mi
- Network: ~1-5MB/min to aggregator (depends on event volume)

The aggregator provides significant benefits:
- Single API endpoint for cluster-wide monitoring
- Event correlation across nodes
- Reduced client connections to individual agents
- Centralized storage and querying
