#!/bin/bash
set -e

# eBPF Monitor Kubernetes Deployment Script

REGISTRY=${REGISTRY:-"localhost:5000"}
TAG=${TAG:-"latest"}
NAMESPACE=${NAMESPACE:-"ebpf-system"}

function usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  build     Build Docker images"
    echo "  push      Push Docker images to registry"  
    echo "  deploy    Deploy to Kubernetes"
    echo "  undeploy  Remove from Kubernetes"
    echo "  status    Check deployment status"
    echo "  logs      Show logs"
    echo "  all       Build, push, and deploy"
    echo ""
    echo "Options:"
    echo "  --registry REGISTRY  Docker registry (default: $REGISTRY)"
    echo "  --tag TAG           Image tag (default: $TAG)"
    echo "  --namespace NS      Kubernetes namespace (default: $NAMESPACE)"
    echo ""
    echo "Examples:"
    echo "  $0 all --registry my-registry.com --tag v1.0.0"
    echo "  $0 deploy --namespace monitoring"
    exit 1
}

function build() {
    echo "🔨 Building Docker images..."
    make docker-build REGISTRY=$REGISTRY TAG=$TAG
}

function push() {
    echo "📤 Pushing Docker images..."
    make docker-push REGISTRY=$REGISTRY TAG=$TAG
}

function deploy() {
    echo "🚀 Deploying to Kubernetes namespace: $NAMESPACE..."
    
    # Update image references in manifests if needed
    if [[ "$REGISTRY" != "localhost:5000" ]] || [[ "$TAG" != "latest" ]]; then
        echo "📝 Updating image references..."
        sed -i.bak "s|ebpf-monitor:latest|$REGISTRY/ebpf-server:$TAG|g" kubernetes/daemonset.yaml
        sed -i.bak "s|ebpf-aggregator:latest|$REGISTRY/ebpf-aggregator:$TAG|g" kubernetes/aggregator-deployment.yaml
    fi
    
    make k8s-deploy
    
    # Restore original manifests
    if [[ -f kubernetes/daemonset.yaml.bak ]]; then
        mv kubernetes/daemonset.yaml.bak kubernetes/daemonset.yaml
        mv kubernetes/aggregator-deployment.yaml.bak kubernetes/aggregator-deployment.yaml
    fi
}

function undeploy() {
    echo "🗑️ Removing from Kubernetes..."
    make k8s-undeploy
}

function status() {
    echo "📊 Checking deployment status..."
    make k8s-status
}

function logs() {
    echo "📋 Showing logs..."
    echo ""
    echo "Aggregator logs:"
    make k8s-logs &
    sleep 2
    echo ""
    echo "Agent logs (first 50 lines):"
    make k8s-logs-agents
}

function all() {
    build
    push
    deploy
}

# Parse command line arguments
COMMAND=""
while [[ $# -gt 0 ]]; do
    case $1 in
        build|push|deploy|undeploy|status|logs|all)
            COMMAND="$1"
            shift
            ;;
        --registry)
            REGISTRY="$2"
            shift 2
            ;;
        --tag)
            TAG="$2"
            shift 2
            ;;
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if [[ -z "$COMMAND" ]]; then
    echo "Error: No command specified"
    usage
fi

# Execute command
case $COMMAND in
    build)
        build
        ;;
    push)
        push
        ;;
    deploy)
        deploy
        ;;
    undeploy)
        undeploy
        ;;
    status)
        status
        ;;
    logs)
        logs
        ;;
    all)
        all
        ;;
esac

echo "✅ Command '$COMMAND' completed successfully!"
