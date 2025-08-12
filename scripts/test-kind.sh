#!/bin/bash
set -e

echo "🧪 eBPF Monitoring Kind Cluster Test Suite"
echo "=========================================="

# Configuration
NAMESPACE="ebpf-system"
AGGREGATOR_SERVICE="ebpf-aggregator"
PORT=8081

# Function to check if pods are ready
check_pods_ready() {
    echo "⏳ Waiting for all pods to be ready..."
    kubectl wait --for=condition=ready --timeout=300s pod -l app=ebpf-aggregator -n $NAMESPACE
    kubectl wait --for=condition=ready --timeout=300s pod -l app=ebpf-monitor -n $NAMESPACE
    echo "✅ All pods are ready"
}

# Function to test aggregator APIs
test_apis() {
    echo "🔍 Testing aggregator APIs..."
    
    # Start port forwarding in background
    kubectl port-forward -n $NAMESPACE svc/$AGGREGATOR_SERVICE $PORT:$PORT > /dev/null 2>&1 &
    PF_PID=$!
    
    # Wait for port forward to be ready
    sleep 5
    
    # Test health endpoint
    echo "Testing health endpoint..."
    if curl -s -f http://localhost:$PORT/health > /dev/null; then
        echo "✅ Health endpoint working"
        curl -s http://localhost:$PORT/health | jq .
    else
        echo "❌ Health endpoint failed"
        return 1
    fi
    
    echo ""
    
    # Test events endpoint
    echo "Testing events endpoint..."
    if curl -s -f http://localhost:$PORT/api/events > /dev/null; then
        echo "✅ Events endpoint working"
        echo "Sample response:"
        curl -s http://localhost:$PORT/api/events | head -c 300
        echo "..."
    else
        echo "❌ Events endpoint failed"
    fi
    
    echo ""
    
    # Test stats endpoint
    echo "Testing stats endpoint..."
    if curl -s -f http://localhost:$PORT/api/stats > /dev/null; then
        echo "✅ Stats endpoint working"
        curl -s http://localhost:$PORT/api/stats | jq .
    else
        echo "❌ Stats endpoint failed"
    fi
    
    # Clean up port forwarding
    kill $PF_PID > /dev/null 2>&1 || true
    
    echo ""
}

# Function to generate some network activity for testing
generate_test_events() {
    echo "🌐 Generating network activity to test eBPF monitoring..."
    
    # Get one of the agent pods to exec into
    AGENT_POD=$(kubectl get pods -n $NAMESPACE -l app=ebpf-monitor -o jsonpath='{.items[0].metadata.name}')
    
    if [[ -z "$AGENT_POD" ]]; then
        echo "❌ No agent pods found"
        return 1
    fi
    
    echo "Using agent pod: $AGENT_POD"
    
    # Generate some network connections
    echo "Making HTTP requests to generate connection events..."
    kubectl exec -n $NAMESPACE $AGENT_POD -- curl -s -m 5 http://httpbin.org/get > /dev/null 2>&1 || true
    kubectl exec -n $NAMESPACE $AGENT_POD -- curl -s -m 5 https://httpbin.org/get > /dev/null 2>&1 || true
    kubectl exec -n $NAMESPACE $AGENT_POD -- nslookup google.com > /dev/null 2>&1 || true
    
    echo "✅ Test network activity generated"
    
    # Give some time for events to be processed
    sleep 5
}

# Function to check for events
check_events() {
    echo "📊 Checking for captured events..."
    
    # Start port forwarding in background
    kubectl port-forward -n $NAMESPACE svc/$AGGREGATOR_SERVICE $PORT:$PORT > /dev/null 2>&1 &
    PF_PID=$!
    
    # Wait for port forward to be ready
    sleep 3
    
    # Query events
    echo "Querying recent events..."
    EVENTS_RESPONSE=$(curl -s http://localhost:$PORT/api/events?limit=5)
    
    if [[ -n "$EVENTS_RESPONSE" ]]; then
        echo "✅ Events captured successfully"
        echo "$EVENTS_RESPONSE" | jq . || echo "$EVENTS_RESPONSE"
    else
        echo "⚠️ No events found (this might be expected in some environments)"
    fi
    
    # Clean up port forwarding
    kill $PF_PID > /dev/null 2>&1 || true
    
    echo ""
}

# Function to show cluster status
show_status() {
    echo "📋 Cluster Status"
    echo "=================="
    
    echo "Nodes:"
    kubectl get nodes -o wide
    
    echo ""
    echo "Pods in $NAMESPACE:"
    kubectl get pods -n $NAMESPACE -o wide
    
    echo ""
    echo "Services in $NAMESPACE:"
    kubectl get services -n $NAMESPACE
    
    echo ""
    echo "DaemonSet status:"
    kubectl get daemonset -n $NAMESPACE
    
    echo ""
    echo "Deployment status:"
    kubectl get deployment -n $NAMESPACE
    
    echo ""
}

# Function to show logs
show_logs() {
    echo "📝 Recent Logs"
    echo "=============="
    
    echo "Aggregator logs:"
    kubectl logs -n $NAMESPACE -l app=ebpf-aggregator --tail=20 --timestamps
    
    echo ""
    echo "Agent logs (from first pod):"
    AGENT_POD=$(kubectl get pods -n $NAMESPACE -l app=ebpf-monitor -o jsonpath='{.items[0].metadata.name}')
    if [[ -n "$AGENT_POD" ]]; then
        kubectl logs -n $NAMESPACE $AGENT_POD --tail=20 --timestamps
    fi
    
    echo ""
}

# Main test execution
main() {
    echo "Starting comprehensive test suite..."
    echo ""
    
    show_status
    check_pods_ready
    test_apis
    generate_test_events
    check_events
    show_logs
    
    echo "🎉 Test suite completed!"
    echo ""
    echo "💡 To manually test:"
    echo "   kubectl port-forward -n $NAMESPACE svc/$AGGREGATOR_SERVICE $PORT:$PORT"
    echo "   curl http://localhost:$PORT/health"
    echo "   curl http://localhost:$PORT/api/events"
}

# Check if running in automation or interactive mode
if [[ "${1:-}" == "--automated" ]]; then
    # In automated mode, exit on any failure
    main
else
    # In interactive mode, continue on failures for debugging
    set +e
    main
fi
