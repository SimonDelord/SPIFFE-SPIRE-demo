# OIDC / SPIFFE / SPIRE - Technical Deep Dive

This document provides detailed technical explanations of the network stacks and protocols involved in OIDC, TLS, mTLS, and SPIFFE.

---

## Table of Contents

1. [TLS vs mTLS Network Stack](#tls-vs-mtls-network-stack)
2. [OAuth 2.0 / OIDC Stack](#oauth-20--oidc-stack)
3. [Where Identity Lives in the Stack](#where-identity-lives-in-the-stack)

---

## TLS vs mTLS Network Stack

### Standard TLS (Server Authentication Only)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TLS (One-Way Authentication)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   CLIENT                                              SERVER                 │
│   ──────                                              ──────                 │
│                                                                              │
│   ┌─────────────────┐                          ┌─────────────────┐          │
│   │   Application   │  HTTP Request            │   Application   │          │
│   │     Layer       │  (e.g., GET /api)        │     Layer       │          │
│   │    (Layer 7)    │ ─────────────────────►   │    (Layer 7)    │          │
│   ├─────────────────┤                          ├─────────────────┤          │
│   │   Presentation  │                          │   Presentation  │          │
│   │     Layer       │                          │     Layer       │          │
│   │    (Layer 6)    │                          │    (Layer 6)    │          │
│   ├─────────────────┤                          ├─────────────────┤          │
│   │     Session     │                          │     Session     │          │
│   │     Layer       │    TLS Handshake         │     Layer       │          │
│   │    (Layer 5)    │ ◄───────────────────►    │    (Layer 5)    │          │
│   │                 │                          │                 │          │
│   │   ┌─────────┐   │                          │   ┌─────────┐   │          │
│   │   │   TLS   │   │  Server presents cert    │   │   TLS   │   │          │
│   │   │         │◄──┼──────────────────────────┼───│  🔐     │   │          │
│   │   │    ❓   │   │  Client verifies server  │   │  Cert   │   │          │
│   │   │ No cert │   │                          │   │         │   │          │
│   │   └─────────┘   │                          │   └─────────┘   │          │
│   ├─────────────────┤                          ├─────────────────┤          │
│   │   Transport     │                          │   Transport     │          │
│   │     Layer       │    TCP Connection        │     Layer       │          │
│   │    (Layer 4)    │ ◄───────────────────►    │    (Layer 4)    │          │
│   ├─────────────────┤                          ├─────────────────┤          │
│   │    Network      │                          │    Network      │          │
│   │     Layer       │    IP Packets            │     Layer       │          │
│   │    (Layer 3)    │ ◄───────────────────►    │    (Layer 3)    │          │
│   ├─────────────────┤                          ├─────────────────┤          │
│   │   Data Link     │                          │   Data Link     │          │
│   │    (Layer 2)    │                          │    (Layer 2)    │          │
│   ├─────────────────┤                          ├─────────────────┤          │
│   │   Physical      │                          │   Physical      │          │
│   │    (Layer 1)    │                          │    (Layer 1)    │          │
│   └─────────────────┘                          └─────────────────┘          │
│                                                                              │
│   ✅ Server is authenticated (client verifies server's certificate)         │
│   ❌ Client is NOT authenticated at TLS layer                               │
│   ❓ Client identity must be verified at Application Layer (JWT, API key)   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### mTLS (Mutual Authentication)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       mTLS (Two-Way Authentication)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   CLIENT                                              SERVER                 │
│   ──────                                              ──────                 │
│                                                                              │
│   ┌─────────────────┐                          ┌─────────────────┐          │
│   │   Application   │  HTTP Request            │   Application   │          │
│   │     Layer       │  (identity already       │     Layer       │          │
│   │    (Layer 7)    │   verified below!)       │    (Layer 7)    │          │
│   ├─────────────────┤ ─────────────────────►   ├─────────────────┤          │
│   │   Presentation  │                          │   Presentation  │          │
│   │     Layer       │                          │     Layer       │          │
│   │    (Layer 6)    │                          │    (Layer 6)    │          │
│   ├─────────────────┤                          ├─────────────────┤          │
│   │     Session     │                          │     Session     │          │
│   │     Layer       │    mTLS Handshake        │     Layer       │          │
│   │    (Layer 5)    │ ◄───────────────────►    │    (Layer 5)    │          │
│   │                 │                          │                 │          │
│   │   ┌─────────┐   │  1. Server sends cert    │   ┌─────────┐   │          │
│   │   │   TLS   │   │◄─────────────────────────│   │   TLS   │   │          │
│   │   │  🔐     │   │                          │   │  🔐     │   │          │
│   │   │  Cert   │   │  2. Client sends cert    │   │  Cert   │   │          │
│   │   │         │───┼─────────────────────────►│   │         │   │          │
│   │   │ (SVID)  │   │                          │   │ (SVID)  │   │          │
│   │   └─────────┘   │  3. Both verify certs    │   └─────────┘   │          │
│   │                 │                          │                 │          │
│   ├─────────────────┤                          ├─────────────────┤          │
│   │   Transport     │                          │   Transport     │          │
│   │     Layer       │    TCP Connection        │     Layer       │          │
│   │    (Layer 4)    │ ◄───────────────────►    │    (Layer 4)    │          │
│   ├─────────────────┤                          ├─────────────────┤          │
│   │    Network      │                          │    Network      │          │
│   │     Layer       │    IP Packets            │     Layer       │          │
│   │    (Layer 3)    │ ◄───────────────────►    │    (Layer 3)    │          │
│   ├─────────────────┤                          ├─────────────────┤          │
│   │   Data Link     │                          │   Data Link     │          │
│   │    (Layer 2)    │                          │    (Layer 2)    │          │
│   ├─────────────────┤                          ├─────────────────┤          │
│   │   Physical      │                          │   Physical      │          │
│   │    (Layer 1)    │                          │    (Layer 1)    │          │
│   └─────────────────┘                          └─────────────────┘          │
│                                                                              │
│   ✅ Server is authenticated (client verifies server's certificate)         │
│   ✅ Client is authenticated (server verifies client's certificate)         │
│   ✅ Identity verified BEFORE any application data is exchanged             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### TLS Handshake Comparison

#### TLS Handshake (Server Auth Only)

```
   Client                                              Server
      │                                                   │
      │─────────── 1. ClientHello ──────────────────────►│
      │                                                   │
      │◄────────── 2. ServerHello ───────────────────────│
      │◄────────── 3. Server Certificate ────────────────│  🔐
      │◄────────── 4. ServerHelloDone ───────────────────│
      │                                                   │
      │  (Client validates server cert)                   │
      │                                                   │
      │─────────── 5. ClientKeyExchange ────────────────►│
      │─────────── 6. ChangeCipherSpec ─────────────────►│
      │─────────── 7. Finished ─────────────────────────►│
      │                                                   │
      │◄────────── 8. ChangeCipherSpec ──────────────────│
      │◄────────── 9. Finished ──────────────────────────│
      │                                                   │
      │◄═══════════ Encrypted Channel ══════════════════►│
      │                                                   │
      │  ❓ Server doesn't know who client is!            │
```

#### mTLS Handshake (Mutual Auth)

```
   Client                                              Server
      │                                                   │
      │─────────── 1. ClientHello ──────────────────────►│
      │                                                   │
      │◄────────── 2. ServerHello ───────────────────────│
      │◄────────── 3. Server Certificate ────────────────│  🔐
      │◄────────── 4. CertificateRequest ────────────────│  ← NEW!
      │◄────────── 5. ServerHelloDone ───────────────────│
      │                                                   │
      │  (Client validates server cert)                   │
      │                                                   │
      │─────────── 6. Client Certificate ───────────────►│  🔐 ← NEW!
      │─────────── 7. ClientKeyExchange ────────────────►│
      │─────────── 8. CertificateVerify ────────────────►│  ← NEW!
      │─────────── 9. ChangeCipherSpec ─────────────────►│
      │─────────── 10. Finished ────────────────────────►│
      │                                                   │
      │  (Server validates client cert)                   │  ← NEW!
      │                                                   │
      │◄────────── 11. ChangeCipherSpec ─────────────────│
      │◄────────── 12. Finished ─────────────────────────│
      │                                                   │
      │◄═══════════ Encrypted Channel ══════════════════►│
      │                                                   │
      │  ✅ Server knows client identity from certificate │
```

---

### TLS vs mTLS Summary

| Aspect | TLS | mTLS |
|--------|-----|------|
| Server Cert | ✅ Required | ✅ Required |
| Client Cert | ❌ Not used | ✅ Required |
| Server verified | ✅ Yes | ✅ Yes |
| Client verified | ❌ No (at TLS layer) | ✅ Yes |
| Auth layer | Application (JWT, etc) | Transport (TLS) |
| Auth timing | After connection | During handshake |
| Zero Trust | ❌ Partial | ✅ Full |
| SPIFFE compatible | ⚠️ Server only | ✅ Both sides |
| Use case | Web browsers, APIs | Service-to-service |

---

## OAuth 2.0 / OIDC Stack

OAuth/OIDC operates at the **Application Layer** - it doesn't participate in TLS at all.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         OAuth 2.0 / OIDC Stack                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   CLIENT                    AUTHORIZATION              RESOURCE              │
│   (App)                     SERVER (IdP)               SERVER (API)          │
│                                                                              │
│   ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐     │
│   │   Application   │      │   Application   │      │   Application   │     │
│   │     Layer       │      │     Layer       │      │     Layer       │     │
│   │    (Layer 7)    │      │    (Layer 7)    │      │    (Layer 7)    │     │
│   │                 │      │                 │      │                 │     │
│   │  ┌───────────┐  │      │  ┌───────────┐  │      │  ┌───────────┐  │     │
│   │  │  OAuth/   │  │      │  │  OAuth/   │  │      │  │   Token   │  │     │
│   │  │  OIDC     │  │      │  │  OIDC     │  │      │  │ Validator │  │     │
│   │  │  Client   │  │      │  │  Server   │  │      │  │           │  │     │
│   │  └───────────┘  │      │  └───────────┘  │      │  └───────────┘  │     │
│   │        │        │      │        │        │      │        ▲        │     │
│   │        │        │      │        │        │      │        │        │     │
│   │   HTTP Request  │      │   HTTP Response │      │  Authorization  │     │
│   │   with tokens   │      │   with tokens   │      │  Bearer <token> │     │
│   │        │        │      │        │        │      │        │        │     │
│   ├────────┼────────┤      ├────────┼────────┤      ├────────┼────────┤     │
│   │   TLS (HTTPS)   │      │   TLS (HTTPS)   │      │   TLS (HTTPS)   │     │
│   │    (Layer 5)    │      │    (Layer 5)    │      │    (Layer 5)    │     │
│   │                 │      │                 │      │                 │     │
│   │  Encrypted but  │      │                 │      │  Encrypted but  │     │
│   │  NO client cert │      │                 │      │  NO client cert │     │
│   ├─────────────────┤      ├─────────────────┤      ├─────────────────┤     │
│   │   TCP/IP        │      │   TCP/IP        │      │   TCP/IP        │     │
│   │  (Layer 3-4)    │      │  (Layer 3-4)    │      │  (Layer 3-4)    │     │
│   └─────────────────┘      └─────────────────┘      └─────────────────┘     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### OAuth 2.0 Authorization Code Flow

```
   User          Client App         Authorization Server      Resource Server
    │                │                      │                       │
    │  1. Click      │                      │                       │
    │  "Login"       │                      │                       │
    │───────────────►│                      │                       │
    │                │                      │                       │
    │                │  2. Redirect to      │                       │
    │◄───────────────│  /authorize          │                       │
    │                │  ?client_id=xxx      │                       │
    │                │  &redirect_uri=xxx   │                       │
    │                │  &scope=openid       │                       │
    │                │                      │                       │
    │  3. Login page │                      │                       │
    │───────────────────────────────────────►                       │
    │                │                      │                       │
    │  4. Enter      │                      │                       │
    │  credentials   │                      │                       │
    │───────────────────────────────────────►                       │
    │                │                      │                       │
    │  5. Redirect   │                      │                       │
    │◄──────────────────────────────────────│                       │
    │  ?code=AUTH_CODE                      │                       │
    │                │                      │                       │
    │  6. Follow     │                      │                       │
    │  redirect      │                      │                       │
    │───────────────►│                      │                       │
    │                │                      │                       │
    │                │  7. POST /token      │                       │
    │                │  code=AUTH_CODE      │                       │
    │                │  client_secret=xxx   │                       │
    │                │─────────────────────►│                       │
    │                │                      │                       │
    │                │  8. {                │                       │
    │                │    access_token,     │                       │
    │                │    id_token,         │                       │
    │                │    refresh_token     │                       │
    │                │  }                   │                       │
    │                │◄─────────────────────│                       │
    │                │                      │                       │
    │                │  9. GET /api/data    │                       │
    │                │  Authorization:      │                       │
    │                │  Bearer <token>      │                       │
    │                │─────────────────────────────────────────────►│
    │                │                      │                       │
    │                │  10. Validate token  │                       │
    │                │  (JWKS or introspect)│◄──────────────────────│
    │                │                      │──────────────────────►│
    │                │                      │                       │
    │                │  11. { data }        │                       │
    │                │◄─────────────────────────────────────────────│
    │                │                      │                       │
    │  12. Show data │                      │                       │
    │◄───────────────│                      │                       │
```

---

### OAuth 2.0 Client Credentials Flow (M2M)

```
   Service A              Authorization Server           Service B
   (Client)               (Keycloak)                     (API)
       │                        │                           │
       │  1. POST /token        │                           │
       │  grant_type=           │                           │
       │    client_credentials  │                           │
       │  client_id=xxx         │                           │
       │  client_secret=xxx     │                           │
       │───────────────────────►│                           │
       │                        │                           │
       │  2. {                  │                           │
       │    access_token: "eyJ.."                           │
       │    token_type: "Bearer"                            │
       │    expires_in: 300     │                           │
       │  }                     │                           │
       │◄───────────────────────│                           │
       │                        │                           │
       │  3. GET /api/resource  │                           │
       │  Authorization: Bearer eyJ..                       │
       │────────────────────────────────────────────────────►
       │                        │                           │
       │                        │  4. Validate JWT          │
       │                        │◄──────────────────────────│
       │                        │  (fetch JWKS)             │
       │                        │──────────────────────────►│
       │                        │                           │
       │  5. { resource_data }  │                           │
       │◄────────────────────────────────────────────────────

   ⚠️  Note: client_secret must be stored securely
   ⚠️  Note: No user involved - machine-to-machine
```

---

### JWT Token Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         JWT Token Structure                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.                    ← Header (Base64)│
│   eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.          ← Payload (Base64)
│   SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c              ← Signature       │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Header (decoded)                                                    │   │
│   │  {                                                                   │   │
│   │    "alg": "RS256",           ← Signing algorithm                    │   │
│   │    "typ": "JWT",             ← Token type                           │   │
│   │    "kid": "abc123"           ← Key ID (for JWKS lookup)             │   │
│   │  }                                                                   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Payload (decoded) - OIDC ID Token                                   │   │
│   │  {                                                                   │   │
│   │    "iss": "https://keycloak.example.com/realms/demo",  ← Issuer     │   │
│   │    "sub": "user-123",                                  ← Subject    │   │
│   │    "aud": "my-app",                                    ← Audience   │   │
│   │    "exp": 1234567890,                                  ← Expiry     │   │
│   │    "iat": 1234567800,                                  ← Issued At  │   │
│   │    "name": "John Doe",                                 ← User info  │   │
│   │    "email": "john@example.com",                                     │   │
│   │    "roles": ["admin", "user"]                          ← Custom     │   │
│   │  }                                                                   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Signature                                                           │   │
│   │                                                                      │   │
│   │  RSASHA256(                                                          │   │
│   │    base64UrlEncode(header) + "." + base64UrlEncode(payload),        │   │
│   │    privateKey                                                        │   │
│   │  )                                                                   │   │
│   │                                                                      │   │
│   │  Verified using public key from JWKS endpoint:                       │   │
│   │  https://keycloak.example.com/realms/demo/protocol/openid-connect/certs
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Where Identity Lives in the Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Where Identity Lives in the Stack                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Layer              OAuth/OIDC                    SPIFFE (mTLS)             │
│   ─────              ──────────                    ─────────────             │
│                                                                              │
│   Application        ┌─────────────────┐          ┌─────────────────┐       │
│   (Layer 7)          │  Authorization: │          │  (Identity      │       │
│                      │  Bearer <JWT>   │          │   already       │       │
│                      │                 │          │   verified      │       │
│                      │  👤 Identity    │          │   below!)       │       │
│                      │  lives HERE     │          │                 │       │
│                      └─────────────────┘          └─────────────────┘       │
│                             │                            │                   │
│   Session/TLS        ┌─────────────────┐          ┌─────────────────┐       │
│   (Layer 5)          │  Server TLS     │          │  mTLS           │       │
│                      │  only           │          │                 │       │
│                      │                 │          │  🔐 Identity    │       │
│                      │  ❌ No client   │          │  lives HERE     │       │
│                      │  identity here  │          │  (X.509 cert)   │       │
│                      └─────────────────┘          └─────────────────┘       │
│                             │                            │                   │
│   Transport          ┌─────────────────┐          ┌─────────────────┐       │
│   (Layer 4)          │      TCP        │          │      TCP        │       │
│                      └─────────────────┘          └─────────────────┘       │
│                                                                              │
│   ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│   Summary:                                                                   │
│   • OAuth/OIDC: Identity in HTTP headers (application layer)                │
│   • SPIFFE:     Identity in TLS handshake (transport layer)                 │
│                                                                              │
│   This is why OAuth can't do mTLS - tokens aren't certificates!             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Takeaways

| Protocol | Identity Type | Layer | Format | Use Case |
|----------|--------------|-------|--------|----------|
| **TLS** | Server only | Transport (L5) | X.509 Certificate | HTTPS websites |
| **mTLS** | Both client & server | Transport (L5) | X.509 Certificates | Service-to-service |
| **OAuth 2.0** | Client (app) | Application (L7) | Access Token | API authorization |
| **OIDC** | User + Client | Application (L7) | JWT ID Token | User authentication |
| **SPIFFE** | Workload | Transport (L5) | X.509-SVID or JWT-SVID | Zero Trust workloads |

---

## Why This Matters

1. **OIDC tokens cannot do mTLS** - they're application-layer constructs, not certificates
2. **SPIFFE bridges the gap** - provides certificate-based identity for workloads
3. **SPIRE OIDC Discovery Provider** - makes SPIFFE identities consumable by OIDC-aware systems
4. **Defense in depth** - you can use both (OIDC for user identity, SPIFFE for workload identity)
