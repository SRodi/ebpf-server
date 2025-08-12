#!/bin/bash
set -e

# Configuration from environment or defaults
KIND_REGISTRY_PORT=${KIND_REGISTRY_PORT:-5001}
BINARY_NAME=${BINARY_NAME:-ebpf-server}
AGGREGATOR_NAME=${AGGREGATOR_NAME:-ebpf-aggregator}
TAG=${TAG:-latest}

echo "🚀 Deploying to kind cluster..."

# Create temporary manifests with correct image references
echo "📝 Updating image references..."

# Backup and update daemonset manifest
cp kubernetes/daemonset.yaml kubernetes/daemonset.yaml.bak
sed "s|ebpf-monitor:latest|localhost:${KIND_REGISTRY_PORT}/${BINARY_NAME}:${TAG}|g" \
    kubernetes/daemonset.yaml.bak > kubernetes/daemonset.yaml

# Backup and update aggregator manifest
cp kubernetes/aggregator-deployment.yaml kubernetes/aggregator-deployment.yaml.bak
sed "s|ebpf-aggregator:latest|localhost:${KIND_REGISTRY_PORT}/${AGGREGATOR_NAME}:${TAG}|g" \
    kubernetes/aggregator-deployment.yaml.bak > kubernetes/aggregator-deployment.yaml

# Apply manifests in order
echo "📋 Applying manifests..."
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/rbac.yaml
kubectl apply -f kubernetes/configmap.yaml
kubectl apply -f kubernetes/services.yaml
kubectl apply -f kubernetes/aggregator-deployment.yaml
kubectl apply -f kubernetes/daemonset.yaml

# Restore original manifests
echo "🔄 Restoring original manifests..."
mv kubernetes/daemonset.yaml.bak kubernetes/daemonset.yaml
mv kubernetes/aggregator-deployment.yaml.bak kubernetes/aggregator-deployment.yaml

echo "⏳ Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/ebpf-aggregator -n ebpf-system
kubectl rollout status daemonset/ebpf-monitor -n ebpf-system --timeout=300s

echo "✅ Deployment completed!"
