#!/bin/bash

set -e

SPIRE_SERVER_POD=$(kubectl get pod -n spire -l app=spire-server -o jsonpath='{.items[0].metadata.name}')

echo "Registering workloads with SPIRE Server..."

# Register a sample workload
kubectl exec -n spire "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://example.org/ns/default/sa/default \
    -parentID spiffe://example.org/ns/spire/sa/spire-agent \
    -selector k8s:ns:default \
    -selector k8s:sa:default

echo "Workload registration complete!"

# List all registered entries
echo ""
echo "Registered entries:"
kubectl exec -n spire "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server entry show
