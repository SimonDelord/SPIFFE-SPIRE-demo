# EDB Use Case: SPIFFE X.509 Certificate Authentication with PostgreSQL

This demo shows how a **SPIFFE-enabled application** uses its **X.509-SVID** (certificate) to authenticate to an **EDB PostgreSQL database**, with the database performing both **authentication** (certificate verification) and **authorization** (mapping certificate identity to database roles).

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [How It Works](#how-it-works)
4. [PostgreSQL Certificate Authentication](#postgresql-certificate-authentication)
5. [SPIFFE Identity Mapping Options](#spiffe-identity-mapping-options)
6. [Implementation Plan](#implementation-plan)
7. [Prerequisites](#prerequisites)
8. [Deployment Steps](#deployment-steps)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)

---

## Overview

### The Scenario

```
┌─────────────────────────────────────────────────────────────────────────────┐
│            SPIFFE X.509 Certificate → PostgreSQL/EDB Authentication         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────────────────────┐     ┌─────────────────────────────┐   │
│   │  SPIFFE-Enabled App             │     │  EDB PostgreSQL             │   │
│   │  (spiffe-demo namespace)        │     │  (edb namespace)            │   │
│   │                                 │     │                             │   │
│   │  Gets X.509-SVID from SPIRE:    │     │  pg_hba.conf:               │   │
│   │  ┌───────────────────────────┐  │     │  ┌───────────────────────┐  │   │
│   │  │ Certificate:              │  │     │  │ hostssl all all ...   │  │   │
│   │  │   SAN: spiffe://trust-    │  │     │  │   cert clientcert=    │  │   │
│   │  │   domain/ns/spiffe-demo/  │══╬═════╬══│   verify-full         │  │   │
│   │  │   sa/db-client-app        │  │ mTLS│  │                       │  │   │
│   │  │                           │  │     │  │ Extracts identity     │  │   │
│   │  │ Private Key               │  │     │  │ from certificate      │  │   │
│   │  └───────────────────────────┘  │     │  └───────────────────────┘  │   │
│   │                                 │     │                             │   │
│   └─────────────────────────────────┘     │  pg_ident.conf:             │   │
│                                           │  ┌───────────────────────┐  │   │
│                                           │  │ Maps SPIFFE ID to     │  │   │
│                                           │  │ database role         │  │   │
│                                           │  │                       │  │   │
│                                           │  │ spiffe-map "..." app  │  │   │
│                                           │  └───────────────────────┘  │   │
│                                           │                             │   │
│                                           │  Database roles:            │   │
│                                           │  - app_read_only            │   │
│                                           │  - app_read_write           │   │
│                                           │  - app_admin                │   │
│                                           └─────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Benefits

| Benefit | Description |
|---------|-------------|
| **No secrets** | No database passwords to manage or rotate |
| **Automatic rotation** | SPIFFE certificates rotate automatically (every few minutes) |
| **Strong identity** | Cryptographic proof of workload identity |
| **Fine-grained authZ** | Map different SPIFFE IDs to different database roles |
| **Audit trail** | Clear identity in database logs |

---

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OpenShift Cluster                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  zero-trust-workload-identity-manager namespace                      │    │
│  │                                                                      │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │    │
│  │  │   SPIRE     │  │   SPIRE     │  │   SPIFFE    │                  │    │
│  │  │   Server    │  │   Agent     │  │   CSI       │                  │    │
│  │  │             │  │  (DaemonSet)│  │   Driver    │                  │    │
│  │  └──────┬──────┘  └──────┬──────┘  └─────────────┘                  │    │
│  │         │                │                                           │    │
│  │         │  Issues SVIDs  │  Delivers to pods                        │    │
│  │         └────────────────┘                                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                          │                                   │
│                                          ▼                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  spiffe-demo namespace                                               │    │
│  │                                                                      │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │  db-client-app Pod                                           │    │    │
│  │  │                                                              │    │    │
│  │  │  ┌──────────────────┐     ┌────────────────────────────┐    │    │    │
│  │  │  │  Application     │     │  SPIFFE Workload API       │    │    │    │
│  │  │  │  Container       │     │  (CSI Volume Mount)        │    │    │    │
│  │  │  │                  │     │                            │    │    │    │
│  │  │  │  Uses:           │◄────│  /spiffe-workload-api/     │    │    │    │
│  │  │  │  - svid.pem      │     │    spiffe-workload-api.sock│    │    │    │
│  │  │  │  - svid-key.pem  │     │                            │    │    │    │
│  │  │  │  - bundle.pem    │     │  Provides:                 │    │    │    │
│  │  │  │                  │     │  - X.509-SVID (cert+key)   │    │    │    │
│  │  │  │                  │     │  - Trust bundle (CA certs) │    │    │    │
│  │  │  └────────┬─────────┘     └────────────────────────────┘    │    │    │
│  │  │           │                                                  │    │    │
│  │  └───────────┼──────────────────────────────────────────────────┘    │    │
│  │              │                                                        │    │
│  └──────────────┼────────────────────────────────────────────────────────┘    │
│                 │                                                              │
│                 │  mTLS Connection (TCP 5432)                                 │
│                 │  Client cert: X.509-SVID                                    │
│                 │  Server cert: EDB certificate                               │
│                 ▼                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  edb namespace                                                       │    │
│  │                                                                      │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │  EDB PostgreSQL Cluster                                      │    │    │
│  │  │                                                              │    │    │
│  │  │  ┌─────────────────────────────────────────────────────┐    │    │    │
│  │  │  │  PostgreSQL Server                                   │    │    │    │
│  │  │  │                                                      │    │    │    │
│  │  │  │  Authentication:                                     │    │    │    │
│  │  │  │  • Verify client cert signed by trusted CA          │    │    │    │
│  │  │  │  • Extract CN or SAN from certificate               │    │    │    │
│  │  │  │                                                      │    │    │    │
│  │  │  │  Authorization:                                      │    │    │    │
│  │  │  │  • Map certificate identity to DB user/role         │    │    │    │
│  │  │  │  • Grant appropriate permissions                     │    │    │    │
│  │  │  └─────────────────────────────────────────────────────┘    │    │    │
│  │  │                                                              │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## How It Works

### Step-by-Step Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Certificate-Based Database Authentication                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. WORKLOAD ATTESTATION                                                   │
│   ──────────────────────                                                    │
│                                                                              │
│   ┌─────────────┐         ┌─────────────┐         ┌─────────────┐          │
│   │ db-client   │  Attest │   SPIRE     │ Verify  │   SPIRE     │          │
│   │ Pod starts  │────────►│   Agent     │────────►│   Server    │          │
│   └─────────────┘         └─────────────┘         └─────────────┘          │
│                                                          │                  │
│                                                          │ Issue X.509-SVID │
│                                                          ▼                  │
│   SPIFFE ID: spiffe://trust-domain/ns/spiffe-demo/sa/db-client-app        │
│                                                                              │
│                                                                              │
│   2. CERTIFICATE DELIVERY                                                   │
│   ───────────────────────                                                   │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Pod: db-client-app                                                  │   │
│   │                                                                      │   │
│   │  CSI Volume Mount:                                                   │   │
│   │  /spiffe-workload-api/                                               │   │
│   │    ├── spiffe-workload-api.sock   (Workload API socket)             │   │
│   │    │                                                                 │   │
│   │  Files obtained via Workload API:                                    │   │
│   │    ├── svid.pem                   (X.509 certificate)                │   │
│   │    ├── svid-key.pem               (Private key)                      │   │
│   │    └── bundle.pem                 (Trust bundle/CA certs)            │   │
│   │                                                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│                                                                              │
│   3. DATABASE CONNECTION (mTLS)                                             │
│   ─────────────────────────────                                             │
│                                                                              │
│   ┌─────────────┐                                      ┌─────────────────┐  │
│   │ db-client   │                                      │  EDB PostgreSQL │  │
│   │             │                                      │                 │  │
│   │  psql       │──── TLS ClientHello ────────────────►│                 │  │
│   │  sslmode=   │                                      │                 │  │
│   │  verify-full│◄─── ServerHello + Server Cert ──────│                 │  │
│   │             │     + CertificateRequest             │                 │  │
│   │  sslcert=   │                                      │                 │  │
│   │  svid.pem   │──── Client Cert (X.509-SVID) ───────►│  Verify cert   │  │
│   │             │     + ClientKeyExchange              │  signed by     │  │
│   │  sslkey=    │                                      │  trusted CA    │  │
│   │  svid-key   │◄─── Finished ───────────────────────│                 │  │
│   │             │                                      │                 │  │
│   │  sslrootca= │═════ Encrypted Connection ══════════►│                 │  │
│   │  bundle.pem │                                      │                 │  │
│   └─────────────┘                                      └─────────────────┘  │
│                                                                              │
│                                                                              │
│   4. AUTHENTICATION (Certificate Verification)                              │
│   ────────────────────────────────────────────                              │
│                                                                              │
│   PostgreSQL checks:                                                        │
│   ✓ Client cert is valid (not expired)                                     │
│   ✓ Client cert is signed by trusted CA (SPIRE CA in our case)            │
│   ✓ Client cert chain is valid                                             │
│                                                                              │
│   → AUTHENTICATION SUCCESS                                                  │
│                                                                              │
│                                                                              │
│   5. AUTHORIZATION (Identity Mapping)                                       │
│   ───────────────────────────────────                                       │
│                                                                              │
│   PostgreSQL extracts identity from certificate:                            │
│                                                                              │
│   Option A: CN (Common Name)                                                │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Certificate CN: "db-client-app"                                     │   │
│   │                        │                                             │   │
│   │                        ▼                                             │   │
│   │  pg_hba.conf: hostssl all all ... cert map=spiffe-map               │   │
│   │  pg_ident.conf: spiffe-map "db-client-app" app_readonly             │   │
│   │                                        │                             │   │
│   │                                        ▼                             │   │
│   │  Database user: app_readonly (with SELECT permissions)              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   Option B: Full SPIFFE ID (via SAN extension parsing)                      │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Certificate SAN URI:                                                │   │
│   │  spiffe://trust-domain/ns/spiffe-demo/sa/db-client-app              │   │
│   │                        │                                             │   │
│   │                        ▼                                             │   │
│   │  Custom mapping or PostgreSQL extension                              │   │
│   │                        │                                             │   │
│   │                        ▼                                             │   │
│   │  Database user based on namespace/serviceaccount                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   → AUTHORIZATION COMPLETE: User mapped to role with specific permissions  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## PostgreSQL Certificate Authentication

### Key Configuration Files

#### postgresql.conf (SSL Settings)

```ini
# Enable SSL
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'
ssl_ca_file = '/path/to/spire-ca-bundle.pem'    # Trust SPIRE CA!

# Require client certificates
ssl_crl_file = ''                                # Optional: CRL
```

#### pg_hba.conf (Authentication Rules)

```
# TYPE  DATABASE  USER  ADDRESS       METHOD   OPTIONS

# Require client certificate authentication for all SSL connections
hostssl  all       all   0.0.0.0/0    cert     clientcert=verify-full map=spiffe-map
```

#### pg_ident.conf (Identity Mapping)

```
# MAPNAME       SYSTEM-USERNAME                           PG-USERNAME

# Map certificate CN to PostgreSQL users
spiffe-map      "db-client-app"                           app_readonly
spiffe-map      "db-admin-app"                            app_admin
spiffe-map      "/^(.*)\.spiffe-demo\.svc$"               app_readonly   # Regex
```

### Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PostgreSQL cert Authentication                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Client connects with:                                                     │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  psql "host=edb-cluster.edb.svc \                                    │   │
│   │        port=5432 \                                                   │   │
│   │        dbname=appdb \                                                │   │
│   │        sslmode=verify-full \                                         │   │
│   │        sslcert=/spiffe/svid.pem \                                    │   │
│   │        sslkey=/spiffe/svid-key.pem \                                 │   │
│   │        sslrootcert=/spiffe/bundle.pem"                               │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│                              │                                               │
│                              ▼                                               │
│                                                                              │
│   PostgreSQL performs:                                                      │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  1. Verify client cert signed by ssl_ca_file (SPIRE CA)             │   │
│   │                              │                                       │   │
│   │                              ▼                                       │   │
│   │  2. Extract CN from certificate                                      │   │
│   │     CN = "db-client-app"                                             │   │
│   │                              │                                       │   │
│   │                              ▼                                       │   │
│   │  3. Apply pg_ident.conf mapping (spiffe-map)                        │   │
│   │     "db-client-app" → "app_readonly"                                 │   │
│   │                              │                                       │   │
│   │                              ▼                                       │   │
│   │  4. Check pg_hba.conf rule matches                                   │   │
│   │     hostssl all all ... cert map=spiffe-map ✓                       │   │
│   │                              │                                       │   │
│   │                              ▼                                       │   │
│   │  5. Login as PostgreSQL user "app_readonly"                         │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## SPIFFE Identity Mapping Options

### The Challenge

SPIFFE X.509-SVIDs put the identity in the **SAN (Subject Alternative Name)** as a URI:
```
SAN URI: spiffe://apps.rosa.rosa-69t6c.hyq5.p3.openshiftapps.com/ns/spiffe-demo/sa/db-client-app
```

PostgreSQL's `cert` auth method traditionally uses the **CN (Common Name)**.

### Options for Mapping

| Option | Approach | Complexity | Pros/Cons |
|--------|----------|------------|-----------|
| **A** | Use CN field | Low | Simple; SPIRE can populate CN |
| **B** | pg_ident.conf patterns | Medium | Flexible regex matching |
| **C** | Custom PostgreSQL extension | High | Full SAN access; complex |
| **D** | spiffe-helper sidecar | Medium | Writes certs with custom CN |

### Option A: CN-Based Mapping (Recommended)

SPIRE can be configured to include a meaningful CN in certificates:

```yaml
# ClusterSPIFFEID configuration
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: db-client-workload
spec:
  spiffeIDTemplate: "spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}"
  podSelector:
    matchLabels:
      app: db-client-app
  # The CN will be derived from the SPIFFE ID or can be customized
```

The resulting certificate:
```
Subject: CN = db-client-app
SAN URI: spiffe://trust-domain/ns/spiffe-demo/sa/db-client-app
```

PostgreSQL mapping:
```
# pg_ident.conf
spiffe-map      "db-client-app"      app_readonly
```

### Option B: Regex-Based Mapping

Use patterns in pg_ident.conf:

```
# pg_ident.conf - Map by service account name pattern
spiffe-map      "/^(.+)-app$/"                    \1_user
spiffe-map      "db-client-app"                   app_readonly
spiffe-map      "db-admin-app"                    app_admin
spiffe-map      "db-batch-processor"              batch_user
```

### Database Roles Setup

```sql
-- Create roles with different permission levels
CREATE ROLE app_readonly;
GRANT CONNECT ON DATABASE appdb TO app_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readonly;

CREATE ROLE app_readwrite;
GRANT CONNECT ON DATABASE appdb TO app_readwrite;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO app_readwrite;

CREATE ROLE app_admin;
GRANT ALL PRIVILEGES ON DATABASE appdb TO app_admin;

-- Create login users that map to these roles
CREATE USER db_client_app WITH LOGIN;
GRANT app_readonly TO db_client_app;

CREATE USER db_admin_app WITH LOGIN;
GRANT app_admin TO db_admin_app;
```

---

## Implementation Plan

### Phase 1: Deploy EDB Operator and Cluster

1. Install EDB Operator in `edb` namespace
2. Create EDB PostgreSQL cluster with SSL enabled
3. Configure cluster to trust SPIRE CA

### Phase 2: Configure Certificate Authentication

1. Export SPIRE CA bundle
2. Configure PostgreSQL for client certificate auth
3. Set up pg_ident.conf mappings
4. Create database roles and users

### Phase 3: Deploy SPIFFE-Enabled Client

1. Create service account for db-client-app
2. Register workload with SPIRE (ClusterSPIFFEID)
3. Deploy client application with CSI driver mount
4. Configure application to use X.509-SVID for database connections

### Phase 4: Test and Verify

1. Verify certificate issuance
2. Test database connectivity
3. Verify identity mapping
4. Test different permission levels

---

## Prerequisites

- OpenShift cluster with:
  - SPIRE/Zero Trust Workload Identity Manager deployed
  - EDB Operator available (from OperatorHub)
- `oc` CLI with cluster-admin access
- SPIRE trust domain configured

---

## Deployment Steps

*Detailed deployment manifests and scripts will be added in subsequent sections.*

### Directory Structure

```
EDB use case/
├── README.md                      # This file
├── k8s/
│   ├── edb/
│   │   ├── namespace.yaml
│   │   ├── edb-cluster.yaml       # EDB PostgreSQL cluster
│   │   ├── ssl-config.yaml        # SSL/TLS configuration
│   │   └── pg-config.yaml         # pg_hba.conf, pg_ident.conf
│   └── db-client/
│       ├── serviceaccount.yaml
│       ├── clusterspiffeid.yaml   # SPIRE registration
│       ├── deployment.yaml
│       ├── configmap.yaml
│       └── service.yaml
├── db-client-app/
│   ├── app.py                     # Python app using psycopg2 with SSL
│   ├── requirements.txt
│   └── Dockerfile
└── scripts/
    ├── export-spire-ca.sh         # Export SPIRE CA bundle
    └── test-connection.sh         # Test database connectivity
```

---

## Testing

### Verify Certificate

```bash
# Check the certificate issued to the pod
oc exec -n spiffe-demo deploy/db-client-app -- \
  openssl x509 -in /spiffe/svid.pem -text -noout

# Expected output includes:
# Subject: CN = db-client-app
# X509v3 Subject Alternative Name:
#     URI:spiffe://trust-domain/ns/spiffe-demo/sa/db-client-app
```

### Test Database Connection

```bash
# From within the pod
oc exec -n spiffe-demo deploy/db-client-app -- \
  psql "host=edb-cluster.edb.svc \
        port=5432 \
        dbname=appdb \
        sslmode=verify-full \
        sslcert=/spiffe/svid.pem \
        sslkey=/spiffe/svid-key.pem \
        sslrootcert=/spiffe/bundle.pem" \
  -c "SELECT current_user, session_user;"
```

### Verify Permissions

```bash
# Should work (SELECT allowed for app_readonly)
psql ... -c "SELECT * FROM users LIMIT 1;"

# Should fail (INSERT not allowed for app_readonly)
psql ... -c "INSERT INTO users (name) VALUES ('test');"
# ERROR: permission denied for table users
```

---

## Troubleshooting

### Certificate Not Trusted

```
FATAL: certificate authentication failed for user "db-client-app"
```

**Check:**
1. SPIRE CA bundle is correctly configured in PostgreSQL `ssl_ca_file`
2. Certificate hasn't expired (SPIFFE certs are short-lived!)
3. Certificate chain is complete

### Identity Mapping Failed

```
FATAL: no pg_ident.conf entry for certificate CN "db-client-app"
```

**Check:**
1. pg_ident.conf has correct mapping
2. Map name in pg_hba.conf matches pg_ident.conf
3. CN in certificate matches expected value

### Connection Refused

```
psql: error: connection to server failed: Connection refused
```

**Check:**
1. EDB cluster is running: `oc get pods -n edb`
2. Service is correctly configured
3. Network policies allow traffic

---

## Next Steps

After completing this setup, you can:

1. **Add more workloads** with different SPIFFE IDs → different database roles
2. **Implement row-level security** based on certificate identity
3. **Set up audit logging** to track which SPIFFE identity accessed what
4. **Configure certificate rotation handling** for long-running connections

---

## Resources

- [SPIFFE Specification](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
- [PostgreSQL SSL/TLS Documentation](https://www.postgresql.org/docs/current/ssl-tcp.html)
- [PostgreSQL Certificate Authentication](https://www.postgresql.org/docs/current/auth-cert.html)
- [EDB Operator Documentation](https://www.enterprisedb.com/docs/)
- [Red Hat Zero Trust Workload Identity Manager](https://docs.redhat.com/en/documentation/openshift_container_platform/4.21/html/security_and_compliance/zero-trust-workload-identity-manager)
