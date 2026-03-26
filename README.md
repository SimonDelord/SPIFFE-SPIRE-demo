# SPIFFE/SPIRE Demo

A demonstration project for [SPIFFE](https://spiffe.io/) (Secure Production Identity Framework for Everyone) and [SPIRE](https://spiffe.io/docs/latest/spire-about/) (SPIFFE Runtime Environment), including integration with OIDC identity providers on OpenShift.

## Overview

This project demonstrates a complete zero-trust identity architecture:

1. **OIDC Authentication (Keycloak)** - User/human identity provider for application authentication
2. **SPIFFE/SPIRE (Zero Trust Workload Identity Manager)** - Workload/machine identity for service-to-service authentication
3. **SPIRE OIDC Discovery Provider** - Exposes SPIFFE identities as OIDC-compatible tokens for external system integration

### Identity Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         OpenShift Cluster                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐           ┌─────────────────────────────────────────┐  │
│  │    Keycloak     │           │  Zero Trust Workload Identity Manager   │  │
│  │   (User IdP)    │           │           (SPIFFE/SPIRE)                │  │
│  │                 │           │                                         │  │
│  │ • User login    │           │ • SPIRE Server (issues SVIDs)          │  │
│  │ • OAuth2/OIDC   │           │ • SPIRE Agents (per node)              │  │
│  │ • ID tokens     │           │ • SPIFFE CSI Driver                    │  │
│  └────────┬────────┘           │ • OIDC Discovery Provider              │  │
│           │                    └──────────────────┬──────────────────────┘  │
│           │                                       │                          │
│           ▼                                       ▼                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         Workloads                                    │    │
│  │                                                                      │    │
│  │   User Identity (Keycloak)  +  Workload Identity (SPIFFE)           │    │
│  │   "Who is the user?"           "Which service is this?"              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### OIDC vs SPIFFE/SPIRE Comparison

| Aspect | OIDC (Keycloak) | SPIFFE/SPIRE |
|--------|-----------------|--------------|
| **Identity type** | Human users | Machines/workloads |
| **Interaction** | Human-in-the-loop | Fully automated |
| **Primary credential** | JWT tokens | X.509 certs or JWTs |
| **Use case** | User login to apps | Service-to-service auth |
| **Token lifetime** | Minutes to hours | Seconds to minutes |
| **Rotation** | User re-authenticates | Automatic, continuous |

## Project Structure

```
.
├── demo-app/                   # Sample OIDC-authenticated Flask application
│   ├── app.py                  # Flask app with Keycloak OIDC integration
│   ├── requirements.txt        # Python dependencies
│   └── Dockerfile              # Container build file
├── k8s/
│   ├── keycloak/               # Keycloak OIDC Identity Provider
│   │   ├── namespace.yaml
│   │   ├── secret.yaml
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── route.yaml
│   ├── demo-app/               # Demo application manifests
│   │   ├── namespace.yaml
│   │   ├── configmap.yaml
│   │   ├── secret.yaml
│   │   ├── imagestream.yaml
│   │   ├── buildconfig.yaml
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── route.yaml
│   └── spire-operator/         # Red Hat Zero Trust Workload Identity Manager
│       ├── namespace.yaml
│       ├── operatorgroup.yaml
│       ├── subscription.yaml
│       ├── zerotrustworkloadidentitymanager.yaml
│       ├── spireserver.yaml
│       ├── spireagent.yaml
│       ├── spiffecsidriver.yaml
│       └── spireoidcdiscoveryprovider.yaml
├── spire-server/               # SPIRE Server configurations (legacy)
├── spire-agent/                # SPIRE Agent configurations (legacy)
├── workloads/                  # Example workload configurations
└── scripts/                    # Helper scripts
```

## Prerequisites

- OpenShift cluster (ROSA, OCP 4.14+, or similar)
- `oc` CLI configured with cluster-admin access
- Docker (for local development)

---

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

# Get Keycloak URL
oc get route keycloak -n keycloak -o jsonpath='{.spec.host}'
```

### Configure Keycloak

1. Access Keycloak admin console at the route URL
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

---

## Part 2: SPIFFE/SPIRE with Zero Trust Workload Identity Manager

The Red Hat Zero Trust Workload Identity Manager provides enterprise-grade SPIFFE/SPIRE deployment on OpenShift.

### Install the Operator

```bash
# Create namespace
oc apply -f k8s/spire-operator/namespace.yaml

# Install operator
oc apply -f k8s/spire-operator/operatorgroup.yaml
oc apply -f k8s/spire-operator/subscription.yaml

# Wait for operator to be ready
oc get csv -n zero-trust-workload-identity-manager -w
```

### Deploy SPIRE Components

Deploy the operands in order:

```bash
# 1. ZeroTrustWorkloadIdentityManager (main CR)
oc apply -f k8s/spire-operator/zerotrustworkloadidentitymanager.yaml

# 2. SPIRE Server
oc apply -f k8s/spire-operator/spireserver.yaml

# 3. SPIRE Agent
oc apply -f k8s/spire-operator/spireagent.yaml

# 4. SPIFFE CSI Driver
oc apply -f k8s/spire-operator/spiffecsidriver.yaml

# 5. SPIRE OIDC Discovery Provider
oc apply -f k8s/spire-operator/spireoidcdiscoveryprovider.yaml
```

### Verify Deployment

```bash
# Check all components are ready
oc get ZeroTrustWorkloadIdentityManager cluster -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}'

# Check pods
oc get pods -n zero-trust-workload-identity-manager

# Check OIDC Discovery endpoint
curl https://$(oc get route spire-oidc-discovery-provider -n zero-trust-workload-identity-manager -o jsonpath='{.spec.host}')/.well-known/openid-configuration
```

### SPIRE Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                Zero Trust Workload Identity Manager                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ SPIRE Server (StatefulSet)                                          │    │
│  │ • Issues X.509 SVIDs and JWT-SVIDs                                  │    │
│  │ • Manages trust domain                                               │    │
│  │ • Stores registration entries                                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                               │
│                              ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ SPIRE Agents (DaemonSet - one per node)                             │    │
│  │ • Node attestation                                                   │    │
│  │ • Workload attestation                                               │    │
│  │ • SVID delivery to workloads                                         │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │                                               │
│                              ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ SPIFFE CSI Driver (DaemonSet)                                       │    │
│  │ • Mounts SPIFFE Workload API socket into pods                       │    │
│  │ • Enables workloads to request SVIDs                                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ OIDC Discovery Provider (Deployment)                                │    │
│  │ • Exposes JWKS for external token validation                        │    │
│  │ • Enables federation with cloud providers (AWS, GCP, Azure)         │    │
│  │ • Endpoint: /.well-known/openid-configuration                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### SPIRE OIDC Discovery Endpoints

The SPIRE OIDC Discovery Provider exposes these endpoints:

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/openid-configuration` | OIDC Discovery document |
| `/keys` | JWKS (JSON Web Key Set) for token verification |

> **Note**: The root path (`/`) returns 404 - this is expected behavior. The OIDC Discovery Provider only serves the standard OIDC endpoints.

---

## Part 3: Integration Scenarios

### Scenario 1: User + Workload Identity

Workloads can have both:
- **User identity** from Keycloak (who is the human user?)
- **Workload identity** from SPIRE (which service is making the request?)

### Scenario 2: Cloud Provider Federation

SPIRE JWT-SVIDs can be used to authenticate to cloud providers:

```bash
# Workload gets JWT-SVID from SPIRE
JWT_SVID=$(spire-agent api fetch jwt -audience aws)

# Exchange for cloud credentials (AWS example)
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::123456789:role/my-role \
  --web-identity-token $JWT_SVID
```

### Scenario 3: Service Mesh Integration

SPIFFE identities can be used with service meshes like Istio for mutual TLS (mTLS) between services.

---

## Troubleshooting

### OIDC Discovery Provider Returns 404 at Root

This is expected behavior. Use `/.well-known/openid-configuration` or `/keys` endpoints.

### SPIRE Agent Not Getting Identity

Restart the OIDC Discovery Provider:
```bash
oc rollout restart deployment spire-spiffe-oidc-discovery-provider -n zero-trust-workload-identity-manager
```

### Check SPIRE Server Logs

```bash
oc logs -n zero-trust-workload-identity-manager statefulset/spire-server -c spire-server
```

---

## Resources

- [SPIFFE Documentation](https://spiffe.io/docs/)
- [SPIRE GitHub Repository](https://github.com/spiffe/spire)
- [Red Hat Zero Trust Workload Identity Manager Documentation](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/zero-trust-workload-identity-manager)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OpenID Connect Specification](https://openid.net/connect/)

## License

MIT
