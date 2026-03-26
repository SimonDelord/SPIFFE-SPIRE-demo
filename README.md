# SPIFFE/SPIRE Demo

A demonstration project for [SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for Everyone) and [SPIRE](https://spiffe.io/docs/latest/spire-about/) (SPIFFE Runtime Environment), including integration with OIDC identity providers.

## Overview

This project demonstrates:

1. **OIDC Authentication** - Using Keycloak as an Identity Provider for user authentication
2. **SPIFFE/SPIRE** - Workload identity for service-to-service authentication (coming soon)
3. **Identity Federation** - How OIDC and SPIFFE/SPIRE can work together

### SPIFFE/SPIRE

SPIFFE provides a secure identity framework for production workloads. SPIRE is the reference implementation that:

- Issues SPIFFE IDs (SVIDs) to workloads
- Provides cryptographic identity attestation
- Enables zero-trust security between services

### OIDC vs SPIFFE/SPIRE

| Aspect | OIDC (Keycloak) | SPIFFE/SPIRE |
|--------|-----------------|--------------|
| **Identity type** | Human users | Machines/workloads |
| **Interaction** | Human-in-the-loop | Fully automated |
| **Primary credential** | JWT tokens | X.509 certs or JWTs |
| **Use case** | User login to apps | Service-to-service auth |

## Project Structure

```
.
├── demo-app/               # Sample OIDC-authenticated Flask application
│   ├── app.py              # Flask application with OIDC integration
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile          # Container build file
├── k8s/
│   ├── keycloak/           # Keycloak OIDC Identity Provider
│   │   ├── namespace.yaml
│   │   ├── secret.yaml
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── route.yaml
│   ├── demo-app/           # Demo application manifests
│   │   ├── namespace.yaml
│   │   ├── configmap.yaml
│   │   ├── secret.yaml
│   │   ├── imagestream.yaml
│   │   ├── buildconfig.yaml
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── route.yaml
│   ├── spire-server.yaml   # SPIRE Server deployment
│   ├── spire-agent.yaml    # SPIRE Agent deployment
│   └── namespace.yaml      # SPIRE namespace
├── spire-server/           # SPIRE Server configurations
├── spire-agent/            # SPIRE Agent configurations
├── workloads/              # Example workload configurations
└── scripts/                # Helper scripts
```

## Prerequisites

- OpenShift cluster (ROSA, OCP, or similar) or Kubernetes cluster
- `oc` or `kubectl` CLI configured
- Docker (for local development)

## Part 1: OIDC Demo with Keycloak

### Deploy Keycloak

```bash
# Create namespace and deploy Keycloak
oc apply -f k8s/keycloak/namespace.yaml
oc apply -f k8s/keycloak/secret.yaml
oc apply -f k8s/keycloak/deployment.yaml
oc apply -f k8s/keycloak/service.yaml
oc apply -f k8s/keycloak/route.yaml

# Wait for Keycloak to be ready
oc rollout status deployment/keycloak -n keycloak
```

### Configure Keycloak

1. Access Keycloak admin console:
   ```bash
   oc get route keycloak -n keycloak -o jsonpath='{.spec.host}'
   ```

2. Login with admin credentials (see `k8s/keycloak/secret.yaml`)

3. Create a new realm called `demo`

4. Create an OIDC client:
   - Client ID: `demo-app`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`
   - Valid Redirect URIs: `https://<demo-app-route>/*`

5. Create a test user with credentials

### Deploy Demo Application

```bash
# Create namespace and configs
oc apply -f k8s/demo-app/namespace.yaml
oc apply -f k8s/demo-app/configmap.yaml
oc apply -f k8s/demo-app/secret.yaml
oc apply -f k8s/demo-app/imagestream.yaml
oc apply -f k8s/demo-app/buildconfig.yaml

# Build the application
oc start-build demo-app --from-dir=demo-app -n demo-app --follow

# Deploy
oc apply -f k8s/demo-app/deployment.yaml
oc apply -f k8s/demo-app/service.yaml
oc apply -f k8s/demo-app/route.yaml

# Get the application URL
oc get route demo-app -n demo-app -o jsonpath='{.spec.host}'
```

### Test OIDC Authentication

1. Open the demo app URL in your browser
2. Click "Sign In with Keycloak"
3. Enter your test user credentials
4. View your authenticated profile and ID token claims

### OIDC Authentication Flow

```
┌──────────┐     1. Click Login      ┌──────────┐
│ Demo App │ ──────────────────────► │ Keycloak │
└──────────┘                         └──────────┘
     │                                     │
     │                              2. Show Login Page
     │                                     │
     │                              3. User Enters Credentials
     │                                     │
     │      4. Redirect with Auth Code     │
     │ ◄─────────────────────────────────  │
     │                                     │
     │      5. Exchange Code for Tokens    │
     │ ────────────────────────────────►   │
     │                                     │
     │      6. Return ID + Access Tokens   │
     │ ◄─────────────────────────────────  │
     │                                     │
     │  7. Display User Profile from       │
     │     ID Token Claims                 │
└──────────────────────────────────────────┘
```

## Part 2: SPIFFE/SPIRE (Coming Soon)

### Deploy SPIRE Server

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/spire-server.yaml
```

### Deploy SPIRE Agent

```bash
kubectl apply -f k8s/spire-agent.yaml
```

### Register Workloads

```bash
./scripts/register-workloads.sh
```

## Part 3: OIDC + SPIFFE Federation (Coming Soon)

This section will demonstrate:
- SPIRE's OIDC Discovery Provider
- Federating SPIFFE identities with cloud providers (AWS, GCP, Azure)
- Workloads using both user identity (OIDC) and service identity (SPIFFE)

## Resources

- [SPIFFE Documentation](https://spiffe.io/docs/)
- [SPIRE GitHub Repository](https://github.com/spiffe/spire)
- [SPIFFE/SPIRE Tutorials](https://spiffe.io/docs/latest/try/)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OpenID Connect Specification](https://openid.net/connect/)

## License

MIT
