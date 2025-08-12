#!/bin/bash
set -e

echo "🧪 Testing eBPF system on Kind cluster..."

# Configuration
NAMESPACE=${NAMESPACE:-ebpf-system}

echo "📊 Checking deployment status..."

# Wait for deployments to be ready
echo "⏳ Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/ebpf-aggregator -n ${NAMESPACE} || {
    echo "❌ Aggregator deployment failed to become available"
    kubectl describe deployment ebpf-aggregator -n ${NAMESPACE}
    exit 1
}

kubectl rollout status daemonset/ebpf-monitor -n ${NAMESPACE} --timeout=300s || {
    echo "❌ Monitor daemonset failed to roll out"
    kubectl describe daemonset ebpf-monitor -n ${NAMESPACE}
    exit 1
}

echo "✅ All deployments are ready!"

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
echo "⏳ Waiting for service to be ready..."
kubectl wait --for=condition=ready pod -l app=ebpf-aggregator -n ${NAMESPACE} --timeout=60s || {
    echo "⚠️  Warning: Aggregator pods may not be fully ready"
}

# Clean up any existing port-forwards
echo "🧹 Cleaning up any existing port-forwards..."
pkill -f "kubectl.*port-forward.*ebpf-aggregator" 2>/dev/null || true
sleep 2

# Find an available port
LOCAL_PORT=8082
check_port() {
    if command -v netstat >/dev/null 2>&1; then
        netstat -an | grep -q ":${1}.*LISTEN" 2>/dev/null
    elif command -v lsof >/dev/null 2>&1; then
        lsof -i ":${1}" >/dev/null 2>&1
    else
        # Fallback: try to connect to the port
        (echo >/dev/tcp/localhost/${1}) >/dev/null 2>&1
    fi
}

while check_port ${LOCAL_PORT}; do
    echo "⚠️  Port ${LOCAL_PORT} is in use, trying $((LOCAL_PORT + 1))"
    LOCAL_PORT=$((LOCAL_PORT + 1))
    if [ ${LOCAL_PORT} -gt 8090 ]; then
        echo "❌ Could not find available port between 8082-8090"
        exit 1
    fi
done

echo "📡 Starting port-forward on localhost:${LOCAL_PORT}..."
kubectl port-forward service/ebpf-aggregator ${LOCAL_PORT}:8081 -n ${NAMESPACE} &
PORT_FORWARD_PID=$!

echo "⏳ Waiting for port-forward to establish..."
sleep 5

# Verify port-forward is working
if ! ps -p ${PORT_FORWARD_PID} > /dev/null 2>&1; then
    echo "❌ Port-forward failed to start"
    exit 1
fi

# Test health endpoint
echo "Health check:"
for i in {1..5}; do
    if curl -s http://localhost:${LOCAL_PORT}/health >/dev/null 2>&1; then
        echo "✅ Health endpoint is accessible"
        curl -s http://localhost:${LOCAL_PORT}/health
        break
    else
        echo "⏳ Attempt $i/5: Health endpoint not ready, waiting..."
        sleep 2
    fi
    if [ $i -eq 5 ]; then
        echo "❌ Health endpoint not accessible after 5 attempts"
    fi
done

# Test events endpoint
echo "Events check:"
curl -s http://localhost:${LOCAL_PORT}/api/events?limit=1 | jq '.' 2>/dev/null || echo "⚠️  Events endpoint not accessible or no data"

# Test stats endpoint
echo "Stats check:"
curl -s http://localhost:${LOCAL_PORT}/api/stats | jq '.' 2>/dev/null || echo "⚠️  Stats endpoint not accessible or no data"

# Cleanup port-forward
echo "🧹 Cleaning up port-forward..."
if [ ! -z "$PORT_FORWARD_PID" ]; then
    kill $PORT_FORWARD_PID 2>/dev/null || true
    wait $PORT_FORWARD_PID 2>/dev/null || true
fi

# Additional cleanup - kill any remaining port-forwards
pkill -f "kubectl.*port-forward.*ebpf-aggregator" 2>/dev/null || true

echo "✅ Testing completed!"
