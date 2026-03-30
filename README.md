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
│   ├── spire-operator/         # Red Hat Zero Trust Workload Identity Manager
│   │   ├── namespace.yaml
│   │   ├── operatorgroup.yaml
│   │   ├── subscription.yaml
│   │   ├── zerotrustworkloadidentitymanager.yaml
│   │   ├── spireserver.yaml
│   │   ├── spireagent.yaml
│   │   ├── spiffecsidriver.yaml
│   │   └── spireoidcdiscoveryprovider.yaml
│   └── spiffe-demo/            # SPIFFE workload identity demo
│       ├── namespace.yaml
│       ├── clusterspiffeid.yaml        # Auto-registers workloads with SPIRE
│       ├── api-server-*.yaml           # API server manifests
│       └── client-app-*.yaml           # Client app manifests
├── spiffe-demo-app/            # SPIFFE demo applications source code
│   ├── api-server.py           # API that validates JWT-SVIDs via OIDC
│   ├── client-app.py           # Client that gets JWT-SVIDs from SPIRE
│   ├── Dockerfile.api
│   ├── Dockerfile.client
│   ├── requirements-api.txt
│   └── requirements-client.txt
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

## Part 3: SPIFFE Workload Identity Demo

This demo shows how workloads use JWT-SVIDs from SPIRE to authenticate to other services, with the receiving service validating tokens via SPIRE's OIDC Discovery Provider.

### Architecture

```
┌─────────────────┐                         ┌─────────────────────────┐
│  Client App     │  1. Get JWT-SVID        │   SPIRE Agent           │
│  (spiffe-demo)  │ ◄───────────────────────│   (via CSI Driver)      │
└────────┬────────┘                         └─────────────────────────┘
         │
         │ 2. Call API with JWT-SVID in Authorization header
         ▼
┌─────────────────┐  3. Fetch JWKS          ┌─────────────────────────┐
│  API Server     │ ────────────────────────►│ SPIRE OIDC Discovery   │
│  (validates     │                          │ Provider               │
│   JWT tokens)   │ ◄────────────────────────│ /keys                  │
└─────────────────┘  4. Validate JWT-SVID    └─────────────────────────┘
         │
         │ 5. Return protected data (if valid)
         ▼
```

### How It Works

1. **ClusterSPIFFEID** - Automatically registers matching pods with SPIRE
2. **SPIFFE CSI Driver** - Mounts the Workload API socket into pods
3. **Client App** - Uses py-spiffe library to get JWT-SVIDs from SPIRE Agent
4. **API Server** - Validates JWT-SVIDs using PyJWT + JWKS from OIDC Discovery Provider

### Deploy the Demo

```bash
# Create namespace
oc apply -f k8s/spiffe-demo/namespace.yaml

# Create service accounts
oc apply -f k8s/spiffe-demo/api-server-serviceaccount.yaml
oc apply -f k8s/spiffe-demo/client-app-serviceaccount.yaml

# Create image streams and build configs
oc apply -f k8s/spiffe-demo/api-server-imagestream.yaml
oc apply -f k8s/spiffe-demo/client-app-imagestream.yaml
oc apply -f k8s/spiffe-demo/api-server-buildconfig.yaml
oc apply -f k8s/spiffe-demo/client-app-buildconfig.yaml

# Build applications
oc start-build spiffe-api-server --from-dir=spiffe-demo-app -n spiffe-demo --follow
oc start-build spiffe-client-app --from-dir=spiffe-demo-app -n spiffe-demo --follow

# Deploy applications
oc apply -f k8s/spiffe-demo/api-server-deployment.yaml
oc apply -f k8s/spiffe-demo/api-server-service.yaml
oc apply -f k8s/spiffe-demo/api-server-route.yaml

oc apply -f k8s/spiffe-demo/client-app-deployment.yaml
oc apply -f k8s/spiffe-demo/client-app-service.yaml
oc apply -f k8s/spiffe-demo/client-app-route.yaml

# Register workload with SPIRE
oc apply -f k8s/spiffe-demo/clusterspiffeid.yaml
```

### Test the Demo

1. **API Server** - Visit the API server URL to see available endpoints
   ```bash
   oc get route spiffe-api-server -n spiffe-demo -o jsonpath='{.spec.host}'
   ```

2. **Client App** - Visit the client app URL and use the interactive buttons:
   ```bash
   oc get route spiffe-client-app -n spiffe-demo -o jsonpath='{.spec.host}'
   ```

   - **Fetch My Identity** - Shows your SPIFFE ID from SPIRE
   - **Get JWT-SVID** - Fetches a JWT token from SPIRE Agent
   - **Call Protected API** - Uses JWT-SVID to authenticate to the API server
   - **Call Public API** - Calls unauthenticated endpoint for comparison

### Key Files

| File | Description |
|------|-------------|
| `clusterspiffeid.yaml` | Tells SPIRE which pods get SPIFFE identities |
| `api-server.py` | Validates JWT-SVIDs using SPIRE's OIDC JWKS endpoint |
| `client-app.py` | Uses py-spiffe library to fetch JWT-SVIDs |

---

## Part 4: Unified API (Multi-Issuer OIDC)

This demo shows an API that trusts **multiple OIDC issuers** - both Keycloak and SPIRE:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Unified API Server                                 │
│                                                                              │
│   Trusted Issuers:                                                          │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ 1. Keycloak (Human users + M2M client credentials)                  │   │
│   │ 2. SPIRE OIDC Discovery (Workload identities via JWT-SVID)         │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└───────────────────────────────▲──────────────────────▲──────────────────────┘
                                │                      │
          ┌─────────────────────┘                      └─────────────────────┐
          │                                                                  │
    Keycloak Token                                               JWT-SVID    │
    (human or M2M)                                         (workload identity)
          │                                                                  │
┌─────────┴─────────┐                                        ┌───────────────┴───┐
│   Human User or   │                                        │   SPIFFE Client   │
│   M2M Service     │                                        │   Workload        │
└───────────────────┘                                        └───────────────────┘
```

### Deploy the Unified API

```bash
# Deploy Unified API (already includes K8s manifests)
oc apply -f k8s/spiffe-demo/unified-api-serviceaccount.yaml
oc apply -f k8s/spiffe-demo/unified-api-imagestream.yaml
oc apply -f k8s/spiffe-demo/unified-api-buildconfig.yaml

# Build
oc start-build unified-api --from-dir=spiffe-demo-app -n spiffe-demo --follow

# Deploy
oc apply -f k8s/spiffe-demo/unified-api-deployment.yaml
oc apply -f k8s/spiffe-demo/unified-api-service.yaml
oc apply -f k8s/spiffe-demo/unified-api-route.yaml
```

### Test All Three Authentication Methods

**1. Human User via Keycloak (browser login)**
- Visit the demo-app and login with testuser
- The ID token can be used to call the Unified API

**2. M2M via Keycloak (client credentials - requires secret)**
```bash
# Get token using client_id and client_secret
TOKEN=$(curl -s -X POST "https://<keycloak-url>/realms/demo/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=m2m-client" \
  -d "client_secret=m2m-secret-12345" | jq -r '.access_token')

# Call Unified API
curl -H "Authorization: Bearer $TOKEN" https://<unified-api-url>/api/protected
```

**3. SPIFFE Workload (no secrets needed)**
- Visit the SPIFFE Client App
- Click "Call Protected API"
- The workload gets a JWT-SVID from SPIRE and calls the Unified API

### Key Insight

| Method | Credentials | Rotation |
|--------|-------------|----------|
| **Human (Keycloak)** | Username/password | Manual re-login |
| **M2M (Keycloak)** | client_id + client_secret | Must rotate secrets |
| **SPIFFE (SPIRE)** | None - attestation based | Automatic (seconds) |

---

## Part 5: Integration Scenarios

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

## Part 6: Bidirectional OIDC ↔ SPIFFE Integration

### Direction 1: SPIFFE → OIDC (Natively Supported ✅)

SPIFFE-enabled workloads can authenticate to OIDC-only systems:

```
┌─────────────────┐     JWT-SVID        ┌─────────────────┐     Validate via JWKS    ┌─────────────────┐
│  SPIFFE App     │ ─────────────────►  │  OIDC-only App  │ ─────────────────────►   │ SPIRE OIDC      │
│                 │                     │                 │                          │ Discovery       │
└─────────────────┘                     └─────────────────┘                          └─────────────────┘
```

**How it works:**
1. SPIRE issues JWT-SVIDs that look like standard OIDC tokens
2. SPIRE OIDC Discovery Provider exposes `/.well-known/openid-configuration` and `/keys`
3. Any OIDC-compatible system can validate JWT-SVIDs using standard JWKS validation

**This is what our demo implements** - the Unified API validates JWT-SVIDs from SPIRE.

---

### Direction 2: OIDC → SPIFFE (Requires Custom Integration ⚠️)

When an OIDC-only client needs to talk to a SPIFFE-enabled service, there is **no built-in feature** in SPIRE. Here are the options:

#### Option A: SPIFFE App Accepts Both (Recommended)

Configure the SPIFFE-enabled app to also accept OIDC tokens:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│   SPIFFE-enabled App (also accepts OIDC)                                    │
│                                                                              │
│   Trusted Sources:                                                           │
│   ┌────────────────────────────┐    ┌────────────────────────────┐          │
│   │ SPIRE (X.509 or JWT-SVID)  │    │ Keycloak (OIDC tokens)     │          │
│   │ For SPIFFE workloads       │    │ For external OIDC clients  │          │
│   └────────────────────────────┘    └────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Pros:** Simple, no additional infrastructure
**Cons:** App must be modified to validate multiple token types

**Example:** Our Unified API demonstrates this pattern.

---

#### Option B: Gateway/Proxy Pattern

Put a SPIFFE-enabled gateway in front of the SPIFFE app:

```
┌─────────────┐   OIDC token     ┌─────────────────┐   mTLS (SVID)   ┌─────────────┐
│  OIDC-only  │ ───────────────► │   API Gateway   │ ──────────────► │  SPIFFE App │
│  Client     │                  │   (SPIFFE)      │                 │  (mTLS only)│
└─────────────┘                  │                 │                 └─────────────┘
                                 │ • Validates     │
                                 │   OIDC token    │
                                 │ • Has own SVID  │
                                 │ • Uses mTLS     │
                                 │   internally    │
                                 └─────────────────┘
```

**Pros:** No changes to backend SPIFFE apps
**Cons:** Additional infrastructure, gateway becomes identity boundary

**Implementation options:**
- Envoy with ext_authz filter
- Istio ingress gateway
- Custom API gateway

---

#### Option C: Token Exchange Service

Build a service that exchanges OIDC tokens for SPIFFE identities:

```
┌─────────────┐   1. OIDC token    ┌─────────────────────┐   3. Proxy SVID   ┌─────────────┐
│  OIDC-only  │ ─────────────────► │   Token Exchange    │ ────────────────► │  OIDC-only  │
│  Client     │                    │   Service           │                   │  Client now │
└─────────────┘                    │   (SPIFFE-enabled)  │                   │  has SVID   │
                                   │                     │                   └──────┬──────┘
                                   │ 2. Validate OIDC    │                          │
                                   │    Request SVID     │                          │
                                   │    for caller       │                          │
                                   └─────────────────────┘                          │
                                                                                    ▼
                                                                             ┌─────────────┐
                                                                             │  SPIFFE App │
                                                                             └─────────────┘
```

**Pros:** Clean separation, true identity conversion
**Cons:** Custom development required, security considerations for identity delegation

**Note:** This is similar to OAuth2 Token Exchange (RFC 8693) but for SPIFFE.

---

#### Option D: Kubernetes OIDC (Already Built-In)

If your OIDC client is a Kubernetes workload, SPIRE already does this!

```
┌─────────────────────────────────────────────────────────────────────────────┐
│   Kubernetes Workload → SPIRE (Built-in!)                                   │
│                                                                              │
│   ┌─────────────┐   K8s SA Token (OIDC!)   ┌─────────────────┐              │
│   │   Pod       │ ───────────────────────► │   SPIRE Agent   │              │
│   │             │                          │                 │              │
│   │             │ ◄─────────────────────── │ Validates K8s   │              │
│   └─────────────┘         SVID             │ token, issues   │              │
│                                            │ SPIFFE SVID     │              │
│                                            └─────────────────┘              │
│                                                                              │
│   The Kubernetes API server IS an OIDC provider!                            │
│   SPIRE's PSAT attestor validates K8s tokens and issues SVIDs.              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Pros:** No custom development, native SPIRE feature
**Cons:** Only works for Kubernetes workloads, not external OIDC providers

---

### Summary: Choosing the Right Approach

| Scenario | Recommended Option |
|----------|-------------------|
| SPIFFE → OIDC | Use SPIRE OIDC Discovery Provider (native) |
| OIDC → SPIFFE (app can be modified) | **Option A** - App accepts both |
| OIDC → SPIFFE (app cannot be modified) | **Option B** - Gateway pattern |
| External OIDC → SPIFFE (identity conversion) | **Option C** - Token Exchange |
| Kubernetes workloads | **Option D** - Already supported via PSAT |

### Key Insight

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   SPIFFE → OIDC:  Easy (SPIRE OIDC Discovery Provider makes it native)     │
│                                                                              │
│   OIDC → SPIFFE:  Requires trust configuration + custom integration         │
│                                                                              │
│   The asymmetry exists because:                                              │
│   • SPIFFE identities are issued via attestation (no secrets)              │
│   • OIDC tokens require explicit trust + credential management              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Part 7: mTLS Between OIDC and SPIFFE Applications

### The Challenge

When App A (OIDC) wants to establish mTLS with App B (SPIFFE), there's a fundamental mismatch:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         The Mismatch                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   OIDC (App A)                          SPIFFE (App B)                       │
│   ────────────                          ─────────────                        │
│   • Identity = JWT tokens               • Identity = X.509-SVIDs             │
│   • Works at Application Layer          • Works at Transport Layer           │
│   • Passed in HTTP headers              • Used in TLS handshake              │
│   • No certificate for mTLS!            • Certificate-based mTLS             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**The problem:** mTLS requires **both sides to present X.509 certificates**. OIDC doesn't give App A a certificate - it gives a JWT token.

### How mTLS Works

```
   Client (App A)                              Server (App B)
       │                                             │
       │──────── 1. ClientHello ───────────────────►│
       │                                             │
       │◄─────── 2. ServerHello + Server Cert ──────│
       │              + CertificateRequest           │
       │                                             │
       │──────── 3. Client Cert + KeyExchange ─────►│
       │                                             │
       │         4. Both verify certificates         │
       │                                             │
       │◄═══════ 5. Encrypted Connection ══════════►│

   ⚠️  App A needs a certificate! OIDC tokens won't work here.
```

### Solution 1: Sidecar/Proxy Pattern (Recommended)

App A uses a SPIFFE-enabled sidecar (like Envoy) that handles mTLS:

```
┌─────────────────────────────────┐           ┌─────────────────────────┐
│         App A's Pod             │           │       App B's Pod       │
│                                 │           │                         │
│  ┌─────────┐    ┌────────────┐  │           │  ┌────────────────────┐ │
│  │  App A  │───►│   Envoy    │  │           │  │      App B         │ │
│  │ (OIDC)  │    │  Sidecar   │══╬══ mTLS ══╬══│    (SPIFFE)        │ │
│  │         │    │ (SPIFFE)   │  │           │  │                    │ │
│  └─────────┘    └────────────┘  │           │  └────────────────────┘ │
│                      │          │           │           │             │
│                 X.509-SVID      │           │      X.509-SVID        │
│                 from SPIRE      │           │      from SPIRE        │
└─────────────────────────────────┘           └─────────────────────────┘
```

**Flow:**
1. App A sends request to local sidecar (localhost)
2. Sidecar establishes mTLS with App B using its X.509-SVID
3. App A's OIDC token can be passed in HTTP headers (optional)
4. App B sees the sidecar's SPIFFE ID + optionally the OIDC token

**This is the Istio/service mesh approach.**

### Solution 2: Server-side TLS + JWT Authentication

Not true mTLS, but achieves mutual authentication at different layers:

```
   App A (OIDC)                                    App B (SPIFFE)
       │                                                │
       │──────── 1. TLS Handshake (server cert only) ──►│
       │              App B presents X.509-SVID         │
       │                                                │
       │◄═══════ 2. Encrypted TLS Connection ═════════►│
       │                                                │
       │──────── 3. HTTP Request ──────────────────────►│
       │              Authorization: Bearer <OIDC JWT>  │
       │                                                │
       │         4. App B validates:                    │
       │            • TLS established (server verified) │
       │            • JWT token valid (client verified) │
```

- ⚠️ This is NOT mTLS - client isn't authenticated at TLS layer
- ✅ But client IS authenticated via JWT at application layer

### Solution 3: App A Gets a Certificate (Traditional PKI)

App A obtains a certificate from a traditional CA:

```
   Traditional PKI                    SPIFFE PKI
   ┌──────────────┐                   ┌──────────────┐
   │  Corporate   │                   │    SPIRE     │
   │     CA       │                   │   Server     │
   └──────┬───────┘                   └──────┬───────┘
          │                                  │
          │ Certificate                      │ X.509-SVID
          ▼                                  ▼
   ┌─────────────┐                    ┌─────────────┐
   │   App A     │═══════ mTLS ══════►│   App B     │
   │  (Cert from │                    │  (SPIFFE)   │
   │   Corp CA)  │                    │             │
   └─────────────┘                    └─────────────┘
```

- ⚠️ App B must trust App A's CA (cross-trust configuration)
- ⚠️ App A's cert is NOT a SPIFFE identity

### Solution 4: Make App A SPIFFE-Enabled

The cleanest solution - both apps use SPIFFE:

```
                          SPIRE Server
                               │
              ┌────────────────┼────────────────┐
              ▼                                 ▼
   ┌─────────────────┐                 ┌─────────────────┐
   │     App A       │                 │     App B       │
   │  (Now SPIFFE!)  │═════ mTLS ═════►│   (SPIFFE)      │
   │                 │                 │                 │
   │  X.509-SVID     │                 │  X.509-SVID     │
   └─────────────────┘                 └─────────────────┘
```

- ✅ True mTLS with SPIFFE on both sides
- ✅ No secrets to manage
- ✅ Automatic certificate rotation

### mTLS Solution Summary

| Approach | mTLS? | Complexity | Best For |
|----------|-------|------------|----------|
| **Sidecar/Proxy** | ✅ Yes | Medium | Service mesh environments |
| **TLS + JWT** | ❌ No (server TLS only) | Low | Quick integration |
| **Traditional PKI** | ✅ Yes | High | Legacy environments |
| **Both SPIFFE** | ✅ Yes | Low | Greenfield, full SPIFFE adoption |

### Key Insight: Layer Mismatch

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   OIDC = Application Layer Identity (JWT in HTTP headers)                   │
│   SPIFFE = Transport Layer Identity (X.509 in TLS handshake)                │
│                                                                              │
│   For TRUE mTLS, you need certificates on both sides.                       │
│   OIDC tokens cannot participate in TLS handshakes.                         │
│                                                                              │
│   The sidecar pattern bridges this gap by giving OIDC apps                  │
│   a SPIFFE identity at the network layer.                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

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
