#!/bin/bash
set -e

# Configuration from environment or defaults
KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-ebpf-test}
KIND_REGISTRY_NAME=${KIND_REGISTRY_NAME:-kind-registry}
KIND_REGISTRY_PORT=${KIND_REGISTRY_PORT:-5001}
BINARY_NAME=${BINARY_NAME:-ebpf-server}
AGGREGATOR_NAME=${AGGREGATOR_NAME:-ebpf-aggregator}
TAG=${TAG:-latest}

echo "📦 Loading Docker images into kind cluster..."

# Build images with localhost registry tag for kind
docker tag "localhost:5000/${BINARY_NAME}:${TAG}" "localhost:${KIND_REGISTRY_PORT}/${BINARY_NAME}:${TAG}"
docker tag "localhost:5000/${AGGREGATOR_NAME}:${TAG}" "localhost:${KIND_REGISTRY_PORT}/${AGGREGATOR_NAME}:${TAG}"

# Push to local registry
echo "Pushing images to local registry..."
docker push "localhost:${KIND_REGISTRY_PORT}/${BINARY_NAME}:${TAG}"
docker push "localhost:${KIND_REGISTRY_PORT}/${AGGREGATOR_NAME}:${TAG}"

echo "✅ Images pushed to kind local registry"
