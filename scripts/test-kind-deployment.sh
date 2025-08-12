#!/bin/bash
set -e

echo "🧪 Testing eBPF system on Kind cluster..."

# Configuration
NAMESPACE=${NAMESPACE:-ebpf-system}

echo "📊 Checking deployment status..."

# Check aggregator deployment
echo "Aggregator deployment status:"
kubectl get deployment ebpf-aggregator -n ${NAMESPACE}

# Check daemonset
echo "DaemonSet status:"
kubectl get daemonset ebpf-monitor -n ${NAMESPACE}

# Get pods
echo "📋 Pods:"
kubectl get pods -n ${NAMESPACE}

# Check aggregator logs
echo "🔍 Aggregator logs (last 20 lines):"
kubectl logs -l app=ebpf-aggregator -n ${NAMESPACE} --tail=20

# Check DaemonSet logs
echo "🔍 Monitor logs (last 20 lines from one pod):"
POD_NAME=$(kubectl get pods -n ${NAMESPACE} -l app=ebpf-monitor -o jsonpath='{.items[0].metadata.name}')
if [ ! -z "$POD_NAME" ]; then
    kubectl logs $POD_NAME -n ${NAMESPACE} --tail=20
fi

# Test aggregator API
echo "🌐 Testing aggregator API..."
kubectl port-forward service/ebpf-aggregator-service 8080:8080 -n ${NAMESPACE} &
PORT_FORWARD_PID=$!

sleep 3

# Test health endpoint
echo "Health check:"
curl -s http://localhost:8080/health || echo "Health endpoint not accessible"

# Test events endpoint
echo "Events check:"
curl -s http://localhost:8080/events | jq '.' || echo "Events endpoint not accessible"

# Test stats endpoint
echo "Stats check:"
curl -s http://localhost:8080/stats | jq '.' || echo "Stats endpoint not accessible"

# Cleanup port-forward
kill $PORT_FORWARD_PID 2>/dev/null || true

echo "✅ Testing completed!"
