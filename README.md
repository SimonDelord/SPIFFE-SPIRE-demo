# SPIFFE/SPIRE Demo

A demonstration project for [SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for Everyone) and [SPIRE](https://spiffe.io/docs/latest/spire-about/) (SPIFFE Runtime Environment).

## Overview

SPIFFE provides a secure identity framework for production workloads. SPIRE is the reference implementation that:

- Issues SPIFFE IDs (SVIDs) to workloads
- Provides cryptographic identity attestation
- Enables zero-trust security between services

## Project Structure

```
.
├── spire-server/       # SPIRE Server configurations
├── spire-agent/        # SPIRE Agent configurations
├── workloads/          # Example workload configurations
├── k8s/                # Kubernetes deployment manifests
└── scripts/            # Helper scripts
```

## Prerequisites

- Docker
- Kubernetes cluster (minikube, kind, or cloud provider)
- kubectl configured
- SPIRE binaries (optional, for local testing)

## Quick Start

1. Deploy SPIRE Server:
   ```bash
   kubectl apply -f k8s/spire-server.yaml
   ```

2. Deploy SPIRE Agent:
   ```bash
   kubectl apply -f k8s/spire-agent.yaml
   ```

3. Register workloads:
   ```bash
   ./scripts/register-workloads.sh
   ```

## Resources

- [SPIFFE Documentation](https://spiffe.io/docs/)
- [SPIRE GitHub Repository](https://github.com/spiffe/spire)
- [SPIFFE/SPIRE Tutorials](https://spiffe.io/docs/latest/try/)

## License

MIT
