#!/bin/bash
set -e

# Configuration from environment or defaults
KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-ebpf-test}
KIND_REGISTRY_NAME=${KIND_REGISTRY_NAME:-kind-registry}
KIND_REGISTRY_PORT=${KIND_REGISTRY_PORT:-5001}

echo "🚀 Creating kind cluster with local registry..."

# Check if cluster already exists
if kind get clusters | grep -q "^${KIND_CLUSTER_NAME}$"; then
    echo "✅ Cluster ${KIND_CLUSTER_NAME} already exists"
    exit 0
fi

echo "📦 Creating local container registry..."
docker run -d --restart=always \
    -p "127.0.0.1:${KIND_REGISTRY_PORT}:5000" \
    --name "${KIND_REGISTRY_NAME}" \
    registry:2 || true

echo "🏗️ Creating kind cluster..."
kind create cluster --name "${KIND_CLUSTER_NAME}" --config kind-config.yaml

echo "🔗 Connecting registry to cluster network..."
docker network connect "kind" "${KIND_REGISTRY_NAME}" || true

echo "📋 Documenting local registry..."
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${KIND_REGISTRY_PORT}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

echo "✅ Kind cluster ${KIND_CLUSTER_NAME} created successfully!"
