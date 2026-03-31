# OIDC / SPIFFE / SPIRE - Technical Deep Dive

This document provides detailed technical explanations of the network stacks and protocols involved in OIDC, TLS, mTLS, and SPIFFE.

---

## Table of Contents

1. [TLS vs mTLS Network Stack](#tls-vs-mtls-network-stack)
2. [OAuth 2.0 / OIDC Stack](#oauth-20--oidc-stack)
3. [Where Identity Lives in the Stack](#where-identity-lives-in-the-stack)
4. [Why Add OIDC/OAuth on Top of TLS?](#why-add-oidcoauth-on-top-of-tls)
5. [OAuth 2.0 / OIDC Sessions](#oauth-20--oidc-sessions)
6. [Multiple OIDC Users on One TLS Connection](#multiple-oidc-users-on-one-tls-connection)
7. [Authentication Methods Beyond HTTP/TLS](#authentication-methods-beyond-httptls)
8. [SPIFFE/SPIRE Authentication: mTLS vs JWT-SVID](#spiffespire-authentication-mtls-vs-jwt-svid)

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

## Why Add OIDC/OAuth on Top of TLS?

A common question: **If TLS already has authentication, why do we need OAuth/OIDC on top?**

### TLS Only Authenticates the Server (by default)

```
Standard TLS (what 99% of HTTPS uses):

   Browser                                    Website
      │                                          │
      │◄──────── Server Certificate ─────────────│  ✅ Server proves identity
      │                                          │
      │   "I know I'm talking to amazon.com"     │
      │   "But amazon.com has NO IDEA who I am"  │  ❌ Client is anonymous
```

When you visit `https://amazon.com`, TLS proves you're talking to the real Amazon. But Amazon doesn't know if you're John, Jane, or a bot.

### mTLS Could Authenticate Clients, But...

Even if we used mTLS (client certificates), it has serious limitations for **human users**:

| Challenge | Why It's a Problem |
|-----------|-------------------|
| **Certificate Provisioning** | How do you give every user a certificate? Install it on every device? |
| **User Experience** | "Please select your certificate" dialogs are confusing |
| **Multi-device** | User has phone, laptop, tablet - separate certs for each? |
| **Revocation** | Fired an employee? Revoking certs across all their devices is hard |
| **No Attributes** | Certificate says "CN=John" but not his email, roles, department, permissions |
| **No Delegation** | Can't say "let this app access my photos but not my email" |
| **No SSO** | Each app needs to trust each certificate separately |
| **Logout** | How do you "log out" of a certificate? You can't. |

### What TLS Authentication Actually Proves

```
┌─────────────────────────────────────────────────────────────────┐
│  What TLS Certificate Proves                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ✅ "This entity possesses the private key for this cert"       │
│  ✅ "This cert was issued by a trusted CA"                      │
│  ✅ "This cert hasn't expired"                                  │
│                                                                  │
│  ❌ "This is user John Smith"                    (identity)     │
│  ❌ "John is an admin"                           (role)         │
│  ❌ "John can access project X"                  (permission)   │
│  ❌ "John works in Engineering dept"             (attribute)    │
│  ❌ "This app can read John's calendar"          (delegation)   │
│  ❌ "John logged in 5 minutes ago"               (session)      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why OAuth/OIDC on Top of TLS

OAuth/OIDC solves **different problems** at a **different layer**:

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│   Layer 7 (Application)     OAuth/OIDC                          │
│   ─────────────────────     ──────────                          │
│                                                                  │
│   WHO is this?              → User identity (sub: "user-123")   │
│   WHAT can they do?         → Scopes (read:photos, write:posts) │
│   WHAT are their attributes?→ Claims (name, email, roles)       │
│   HOW LONG is this valid?   → Token expiry (short-lived)        │
│   CAN they delegate?        → Yes (OAuth is designed for this)  │
│   CAN they log out?         → Yes (revoke tokens)               │
│   Single Sign-On?           → Yes (one IdP, many apps)          │
│                                                                  │
│   ─────────────────────────────────────────────────────────────  │
│                                                                  │
│   Layer 5 (TLS)             Certificate Authentication          │
│   ─────────────────         ──────────────────────              │
│                                                                  │
│   Is the connection secure? → Yes (encryption)                  │
│   Is the server authentic?  → Yes (server cert validation)      │
│   Is the client authentic?  → Only with mTLS (rare for humans)  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Real-World Example: Logging into Spotify with Google

```
With ONLY TLS (hypothetical):
─────────────────────────────
1. You'd need a client certificate
2. Spotify would need to trust Google's CA
3. Google would need to issue you a certificate
4. That cert would need to contain your permissions for Spotify
5. Every time permissions change, new cert needed
6. Can't revoke access without revoking entire cert

With OAuth/OIDC (how it actually works):
────────────────────────────────────────
1. Spotify redirects you to Google
2. You log in with password/2FA (Google's choice)
3. Google asks "Let Spotify see your name and email?"
4. You click "Allow"
5. Spotify gets a token with ONLY the info you approved
6. Token expires in 1 hour
7. You can revoke Spotify's access anytime in Google settings
8. No certificates involved for the user
```

### When to Use What

| Use Case | Solution |
|----------|----------|
| Human users logging into web apps | **OIDC** (on top of TLS) |
| Human users on internal corporate apps | **OIDC** or SAML (on top of TLS) |
| Service-to-service (machines) | **mTLS/SPIFFE** or OAuth Client Credentials |
| Zero Trust workload identity | **SPIFFE/SPIRE with mTLS** |
| APIs accessed by 3rd party apps | **OAuth 2.0** (on top of TLS) |
| High-security internal microservices | **SPIFFE mTLS** (both sides) |

### Summary: TLS and OAuth/OIDC are Complementary

TLS and OAuth/OIDC are **complementary**, not competing:

- **TLS** = Secure the pipe (encryption + server authentication)
- **OAuth/OIDC** = Identify who's using the pipe and what they can do

This is why SPIFFE is powerful for **machines** (where mTLS makes sense) while OIDC remains dominant for **humans** (where usability matters).

---

## OAuth 2.0 / OIDC Sessions

A common question: **Is there a concept of a "session" in OAuth 2.0 or OIDC?**

The answer is nuanced - there are actually **multiple sessions** at different layers:

### The Multiple Sessions in OAuth/OIDC

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Sessions in OAuth 2.0 / OIDC                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────┐      ┌─────────────┐      ┌─────────────┐                 │
│   │   App A     │      │   App B     │      │   App C     │                 │
│   │  (Spotify)  │      │  (Slack)    │      │  (GitHub)   │                 │
│   │             │      │             │      │             │                 │
│   │ ┌─────────┐ │      │ ┌─────────┐ │      │ ┌─────────┐ │                 │
│   │ │ App     │ │      │ │ App     │ │      │ │ App     │ │  ← Application  │
│   │ │ Session │ │      │ │ Session │ │      │ │ Session │ │    Sessions     │
│   │ │ (cookie)│ │      │ │ (cookie)│ │      │ │ (cookie)│ │    (Layer 3)    │
│   │ └─────────┘ │      │ └─────────┘ │      │ └─────────┘ │                 │
│   │             │      │             │      │             │                 │
│   │ ┌─────────┐ │      │ ┌─────────┐ │      │ ┌─────────┐ │                 │
│   │ │ Tokens  │ │      │ │ Tokens  │ │      │ │ Tokens  │ │  ← Token        │
│   │ │ access  │ │      │ │ access  │ │      │ │ access  │ │    Lifecycle    │
│   │ │ refresh │ │      │ │ refresh │ │      │ │ refresh │ │    (Layer 2)    │
│   │ └─────────┘ │      │ └─────────┘ │      │ └─────────┘ │                 │
│   └──────┬──────┘      └──────┬──────┘      └──────┬──────┘                 │
│          │                    │                    │                         │
│          └────────────────────┼────────────────────┘                         │
│                               │                                              │
│                               ▼                                              │
│                    ┌─────────────────────┐                                   │
│                    │   Identity Provider │                                   │
│                    │     (Keycloak)      │                                   │
│                    │                     │                                   │
│                    │   ┌─────────────┐   │  ← IdP/SSO Session               │
│                    │   │ SSO Session │   │    (Layer 1)                     │
│                    │   │  (cookie)   │   │                                   │
│                    │   │             │   │    One session enables            │
│                    │   │  User: John │   │    login to ALL apps              │
│                    │   └─────────────┘   │                                   │
│                    └─────────────────────┘                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Layer 1: IdP/SSO Session

This is the session at the **Identity Provider** (Keycloak, Google, Okta, etc.).

```
┌─────────────────────────────────────────────────────────────────┐
│  IdP Session (SSO Session)                                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WHERE:     Identity Provider (Keycloak)                        │
│  STORED:    Server-side session + browser cookie                │
│  PURPOSE:   Enable Single Sign-On (SSO)                         │
│  LIFETIME:  Configurable (e.g., 8 hours, 30 days)               │
│                                                                  │
│  Example cookie:                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Name: KEYCLOAK_SESSION                                  │    │
│  │  Value: demo/abc123/user-session-id-xyz                  │    │
│  │  Domain: keycloak.example.com                            │    │
│  │  HttpOnly: true                                          │    │
│  │  Secure: true                                            │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  This is what enables:                                           │
│  ✅ "Stay logged in" across multiple apps                       │
│  ✅ No re-authentication when visiting new app                  │
│  ✅ Single logout (end session, log out of all apps)            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Layer 2: Token Lifecycle (Not Really a "Session")

OAuth 2.0 tokens have **lifetimes**, but they're not traditional sessions:

```
┌─────────────────────────────────────────────────────────────────┐
│  Token Lifecycle                                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Access Token                                                    │
│  ────────────                                                    │
│  • Short-lived (5 min - 1 hour typically)                       │
│  • Self-contained (JWT) - no server lookup needed               │
│  • Stateless - IdP doesn't track active access tokens           │
│  • Cannot be "revoked" easily (until expiry)                    │
│                                                                  │
│  Refresh Token                                                   │
│  ─────────────                                                   │
│  • Long-lived (days to months)                                  │
│  • Often tracked server-side (can be revoked)                   │
│  • Used to get new access tokens                                │
│  • This is the closest thing to a "session" in OAuth            │
│                                                                  │
│  Timeline:                                                       │
│  ─────────────────────────────────────────────────────────────  │
│  │ Login │                                                       │
│  │       │──── Access Token (15 min) ────│                      │
│  │       │                               │ expired               │
│  │       │                               │                       │
│  │       │──────── Refresh Token (30 days) ─────────────────│   │
│  │       │                               │                   │   │
│  │       │                    Use refresh │                   │   │
│  │       │                    to get new  │                   │   │
│  │       │                    access token│                   │   │
│  │       │                               ▼                   │   │
│  │       │               ─── New Access Token (15 min) ──│   │   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Layer 3: Application Session

This is **NOT part of OIDC** - it's what each application manages independently:

```
┌─────────────────────────────────────────────────────────────────┐
│  Application Session                                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WHERE:     Each individual application (Spotify, Slack, etc.)  │
│  STORED:    App's own session store + browser cookie            │
│  PURPOSE:   Track logged-in user within the app                 │
│  LIFETIME:  App decides (30 min, 24 hours, "remember me")       │
│                                                                  │
│  Example (Flask app):                                            │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  # After OIDC login completes:                           │    │
│  │  session['user'] = {                                     │    │
│  │      'sub': 'user-123',                                  │    │
│  │      'name': 'John Doe',                                 │    │
│  │      'email': 'john@example.com'                         │    │
│  │  }                                                       │    │
│  │  session['access_token'] = 'eyJ...'                      │    │
│  │  session['refresh_token'] = 'abc...'                     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  The app can:                                                    │
│  • Have its own session timeout (different from IdP)            │
│  • Store tokens in session for API calls                        │
│  • Implement "remember me" independently                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### OIDC Session Management (Optional Spec)

OIDC does define **optional** session management specifications:

| Specification | How It Works |
|--------------|--------------|
| **Session Management** | Hidden iframe polls IdP to detect logout |
| **Front-Channel Logout** | IdP loads logout URLs in hidden iframes |
| **Back-Channel Logout** | IdP sends HTTP POST to apps when user logs out |

```
Back-Channel Logout Example:

   User                App A              IdP              App B
     │                   │                 │                 │
     │  Click "Logout"   │                 │                 │
     │──────────────────►│                 │                 │
     │                   │  POST /logout   │                 │
     │                   │────────────────►│                 │
     │                   │                 │                 │
     │                   │                 │  POST /backchannel-logout
     │                   │                 │────────────────►│
     │                   │                 │  (logout_token) │
     │                   │                 │                 │
     │                   │                 │◄────── 200 OK ──│
     │                   │                 │                 │
     │◄──── Redirect ────│                 │   App B invalidates
     │   to IdP logout   │                 │   user's session
```

### Summary: OAuth 2.0 vs OIDC Sessions

| Aspect | OAuth 2.0 | OIDC |
|--------|-----------|------|
| Protocol defines sessions? | ❌ No | ⚠️ Optional specs |
| Access token = session? | ❌ No (stateless) | ❌ No |
| Refresh token = session? | ⚠️ Sort of (revocable) | ⚠️ Sort of |
| IdP session? | Not defined | ✅ Yes (SSO session) |
| Session management specs? | ❌ No | ✅ Yes (optional) |
| Single logout? | ❌ No | ✅ Yes (optional) |

**Key insight**: OAuth 2.0 was designed to be **stateless** (tokens are self-contained). The "session" concept lives primarily at the **IdP** (for SSO) and at each **application** (for UX), not in the protocol itself.

---

## Multiple OIDC Users on One TLS Connection

A common question: **Can multiple OIDC users share the same TLS connection?**

**Yes, absolutely!** This is a key architectural distinction between TLS and OIDC.

### TLS Connection vs OIDC User Identity

```
┌─────────────────────────────────────────────────────────────────────────────┐
│           Multiple OIDC Users Over One TLS Connection                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Browser/Clients          Load Balancer/Proxy              Backend API     │
│                                                                              │
│   ┌──────────┐                                                              │
│   │  User A  │───┐                                                          │
│   │ (Alice)  │   │                                                          │
│   └──────────┘   │         ┌─────────────────┐         ┌──────────────┐    │
│                  │         │                 │         │              │    │
│   ┌──────────┐   ├────────►│   NGINX /       │         │   Backend    │    │
│   │  User B  │───┤  Many   │   HAProxy /     │═══════► │   API        │    │
│   │  (Bob)   │   │  TLS    │   OpenShift     │  ONE    │   Server     │    │
│   └──────────┘   │  conns  │   Route         │  TLS    │              │    │
│                  │         │                 │  conn   │              │    │
│   ┌──────────┐   │         │  (connection    │  (pool) │              │    │
│   │  User C  │───┘         │   pooling)      │         │              │    │
│   │ (Carol)  │             │                 │         │              │    │
│   └──────────┘             └─────────────────┘         └──────────────┘    │
│                                                                              │
│   Each user has their                        Multiple users' requests       │
│   own TLS connection                         flow over SAME TLS connection  │
│   to the proxy                               to the backend                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### How It Works: Requests Over Shared Connection

```
Single TLS Connection (Proxy → Backend)
════════════════════════════════════════════════════════════════════════════

  Time
   │
   │    ┌──────────────────────────────────────────────────────────────┐
   │    │  HTTP Request #1                                              │
   ▼    │  GET /api/data                                                │
        │  Authorization: Bearer eyJ...Alice's_Token...                 │  ← Alice
        │  X-Request-ID: req-001                                        │
        └──────────────────────────────────────────────────────────────┘
        
        ┌──────────────────────────────────────────────────────────────┐
        │  HTTP Request #2                                              │
        │  POST /api/orders                                             │
        │  Authorization: Bearer eyJ...Bob's_Token...                   │  ← Bob
        │  X-Request-ID: req-002                                        │
        └──────────────────────────────────────────────────────────────┘
        
        ┌──────────────────────────────────────────────────────────────┐
        │  HTTP Request #3                                              │
        │  GET /api/profile                                             │
        │  Authorization: Bearer eyJ...Carol's_Token...                 │  ← Carol
        │  X-Request-ID: req-003                                        │
        └──────────────────────────────────────────────────────────────┘

════════════════════════════════════════════════════════════════════════════
        All three requests flow over the SAME TLS connection!
        The backend identifies users by their JWT tokens, NOT by TLS.
```

### Why This Works

| Layer | What It Authenticates | Scope |
|-------|----------------------|-------|
| **TLS** | The two **endpoints** (machines) | Connection level |
| **OIDC** | The **user** making the request | Request level |

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│   TLS says:    "This connection is between trusted machines"    │
│                "Proxy ←→ Backend are who they claim to be"      │
│                                                                  │
│   OIDC says:   "This specific request is from Alice"            │
│                "This specific request is from Bob"              │
│                "This specific request is from Carol"            │
│                                                                  │
│   They operate at DIFFERENT layers and answer DIFFERENT         │
│   questions!                                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### HTTP/2 Makes This Even More Obvious

HTTP/2 explicitly multiplexes multiple **streams** over a single TLS connection:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     HTTP/2 Multiplexing Over TLS                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Single TLS Connection                                                      │
│   ════════════════════════════════════════════════════════════════════      │
│                                                                              │
│   Stream 1 (Alice): ──────■■■────────■■■■■──────────■■──────────────        │
│   Stream 3 (Bob):   ────■■■■──────■■■──────────■■■■■────────■■──────        │
│   Stream 5 (Carol): ─■■──────■■■■────────■■──────────■■■────────────        │
│                                                                              │
│   ════════════════════════════════════════════════════════════════════      │
│                                                                              │
│   ■ = HTTP frames for that user's request/response                          │
│                                                                              │
│   All interleaved over ONE TLS connection!                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Contrast with mTLS/SPIFFE

With mTLS, the **client certificate** is tied to the connection, not the request:

```
┌─────────────────────────────────────────────────────────────────┐
│  mTLS: Identity is per CONNECTION                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Service A ══════════════════════════════════► Service B       │
│              mTLS connection                                     │
│              Client cert: spiffe://example/service-a             │
│                                                                  │
│   ALL requests on this connection are from "service-a"          │
│   You can't have Service C's requests on this connection        │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│  OIDC: Identity is per REQUEST                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Proxy ════════════════════════════════════════► API           │
│          TLS connection (server auth only)                       │
│                                                                  │
│   Request 1: Authorization: Bearer <Alice's token>              │
│   Request 2: Authorization: Bearer <Bob's token>                │
│   Request 3: Authorization: Bearer <Carol's token>              │
│                                                                  │
│   Different users on SAME connection - identity in headers!     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Summary: TLS vs OIDC Identity Scope

| Aspect | TLS/mTLS | OIDC |
|--------|----------|------|
| Identity scope | Per **connection** | Per **request** |
| Multiple users per connection? | ❌ No (mTLS) | ✅ Yes |
| Where identity lives | TLS handshake | HTTP header |
| Connection pooling friendly? | ⚠️ Complicated | ✅ Yes |
| Use case | Machine-to-machine | Human users, shared infrastructure |

**Key insight**: OIDC's "identity in the request header" design is what enables modern architectures with load balancers, API gateways, CDNs, and connection pooling - where many users' requests flow through shared connections.

---

## Authentication Methods Beyond HTTP/TLS

Not all applications use HTTP or standard TLS authentication. Here's an overview of other authentication mechanisms.

### Database Authentication

Databases typically run on custom protocols (not HTTP) with their own auth mechanisms:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Database Authentication Methods                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────┐                              ┌──────────────────┐        │
│   │   Client     │ ════ TCP (port 5432) ═══════►│   PostgreSQL     │        │
│   │   App        │                              │   Database       │        │
│   └──────────────┘                              └──────────────────┘        │
│                                                                              │
│   Authentication happens INSIDE the protocol, not at TLS layer              │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  Method              │ How It Works                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  Password            │ Username + password sent (often hashed)              │
│  SCRAM-SHA-256       │ Challenge-response, password never sent              │
│  Certificate (mTLS)  │ Client presents X.509 cert during TLS handshake      │
│  Kerberos/GSSAPI     │ Kerberos ticket from KDC                             │
│  LDAP                │ Validates against LDAP/Active Directory              │
│  PAM                 │ Pluggable modules (can chain auth methods)           │
│  Trust               │ Trust based on IP address or hostname (dangerous!)   │
│  Ident               │ Maps OS username to DB username                      │
│  RADIUS              │ External RADIUS server                               │
│  IAM (Cloud)         │ AWS/GCP IAM roles → short-lived credentials          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### PostgreSQL Example (pg_hba.conf)

```
# TYPE  DATABASE  USER        ADDRESS          METHOD
─────────────────────────────────────────────────────────────────
host    all       all         10.0.0.0/8       scram-sha-256    # Password
hostssl all       all         0.0.0.0/0        cert             # mTLS
host    all       admin       192.168.1.0/24   gss              # Kerberos
host    all       readonly    127.0.0.1/32     trust            # No auth!
```

### SASL (Simple Authentication and Security Layer)

Many non-HTTP protocols use SASL as an abstraction layer:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                               SASL Framework                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Protocols that use SASL:                                                   │
│   • LDAP                    • Kafka                                         │
│   • SMTP/IMAP              • MongoDB                                        │
│   • AMQP (RabbitMQ)        • Memcached                                      │
│   • XMPP                   • Cassandra                                      │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         Application Protocol                         │   │
│   │                     (Kafka, LDAP, SMTP, etc.)                       │   │
│   ├─────────────────────────────────────────────────────────────────────┤   │
│   │                              SASL                                    │   │
│   ├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────┤   │
│   │  PLAIN   │  SCRAM   │ GSSAPI   │ EXTERNAL │  OAUTHBEARER  │  ...   │   │
│   │(password)│(SHA-256) │(Kerberos)│  (cert)  │   (OAuth)     │        │   │
│   └──────────┴──────────┴──────────┴──────────┴──────────┴─────────────┘   │
│                                                                              │
│   SASL allows protocols to support multiple auth mechanisms                 │
│   without changing the protocol itself                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Kerberos (Network Authentication)

Used heavily in enterprise environments:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Kerberos Authentication                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                         ┌─────────────────┐                                  │
│                         │       KDC       │                                  │
│                         │ (Key Distribution│                                 │
│                         │     Center)     │                                  │
│                         └────────┬────────┘                                  │
│                                  │                                           │
│            ┌─────────────────────┼─────────────────────┐                    │
│            │                     │                     │                    │
│            ▼                     ▼                     ▼                    │
│   1. Get TGT            2. Get Service           3. Present               │
│   (Ticket Granting      Ticket for DB            Ticket to DB              │
│    Ticket)                                                                  │
│                                                                              │
│   ┌──────────┐                                   ┌──────────┐              │
│   │  Client  │══════════════════════════════════►│ Database │              │
│   │          │  Present Kerberos Service Ticket  │ (port    │              │
│   │          │  (no password sent!)              │  5432)   │              │
│   └──────────┘                                   └──────────┘              │
│                                                                              │
│   ✅ Password never sent over network                                       │
│   ✅ Single Sign-On across services                                         │
│   ✅ Time-limited tickets                                                   │
│   ⚠️ Complex infrastructure (KDC required)                                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Message Queue Authentication

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Message Queue Authentication                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Apache Kafka (port 9092/9093):                                            │
│   ├── SASL/PLAIN (username/password)                                        │
│   ├── SASL/SCRAM-SHA-256                                                    │
│   ├── SASL/GSSAPI (Kerberos)                                                │
│   ├── SASL/OAUTHBEARER (OAuth 2.0 tokens!)                                  │
│   └── SSL/mTLS (certificate-based)                                          │
│                                                                              │
│   RabbitMQ (port 5672):                                                     │
│   ├── PLAIN (username/password)                                             │
│   ├── AMQPLAIN                                                              │
│   ├── EXTERNAL (x509 certificate CN)                                        │
│   └── LDAP backend                                                          │
│                                                                              │
│   Redis (port 6379):                                                        │
│   ├── AUTH command (password only, pre-6.0)                                │
│   ├── ACL (username + password, 6.0+)                                       │
│   └── TLS client certificates                                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### SSH Authentication

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SSH Authentication (port 22)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Methods (in typical priority order):                                       │
│                                                                              │
│   1. Public Key Authentication                                               │
│      ┌─────────┐                           ┌─────────┐                      │
│      │ Client  │──── Public Key ──────────►│ Server  │                      │
│      │ (has    │◄─── Challenge ────────────│(has     │                      │
│      │ private │──── Signed Response ─────►│ public  │                      │
│      │ key)    │                           │ key)    │                      │
│      └─────────┘                           └─────────┘                      │
│                                                                              │
│   2. Certificate Authentication (SSH CA)                                     │
│      Similar to X.509, but SSH-specific certificate format                  │
│                                                                              │
│   3. GSSAPI/Kerberos                                                        │
│      Use existing Kerberos ticket                                           │
│                                                                              │
│   4. Password                                                                │
│      Simple but less secure                                                  │
│                                                                              │
│   5. Keyboard-Interactive                                                    │
│      Multi-factor, prompts (like 2FA codes)                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Cloud IAM Authentication

Modern approach - use cloud IAM instead of static credentials:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Cloud IAM Database Authentication                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   AWS RDS IAM Authentication:                                                │
│                                                                              │
│   ┌──────────┐      1. Get IAM credentials      ┌─────────────┐            │
│   │   App    │◄─────────────────────────────────│  AWS IAM    │            │
│   │ (EC2/EKS)│      (from instance role)        │             │            │
│   └────┬─────┘                                  └─────────────┘            │
│        │                                                                     │
│        │ 2. Generate auth token (valid 15 min)                              │
│        │    aws rds generate-db-auth-token                                  │
│        │                                                                     │
│        ▼                                                                     │
│   ┌──────────┐      3. Connect with token      ┌─────────────┐             │
│   │   App    │═══════════════════════════════►│  RDS MySQL  │             │
│   │          │      (as password)              │  /PostgreSQL│             │
│   └──────────┘                                 └─────────────┘             │
│                                                                              │
│   ✅ No static passwords                                                     │
│   ✅ Short-lived tokens (15 minutes)                                        │
│   ✅ Tied to IAM role/policy                                                │
│   ✅ Auditable via CloudTrail                                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Network-Level Authentication

Authentication before application layer:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Network-Level Authentication                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   IPsec:                                                                     │
│   • Pre-shared keys (PSK)                                                   │
│   • X.509 certificates                                                      │
│   • IKEv2 with EAP                                                          │
│                                                                              │
│   WireGuard:                                                                 │
│   • Curve25519 key pairs                                                    │
│   • No usernames, just public keys                                          │
│                                                                              │
│   802.1X (Port-based Network Access):                                       │
│   • EAP-TLS (certificates)                                                  │
│   • EAP-PEAP (password inside TLS tunnel)                                   │
│   • Used for WiFi and wired network access                                  │
│                                                                              │
│   These authenticate at Layer 2-4, BEFORE any application protocol          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Authentication Method Comparison

| Method | Layer | Secrets | Rotation | Use Case |
|--------|-------|---------|----------|----------|
| **Password** | App | Static secret | Manual | Simple apps |
| **SCRAM** | App | Password (hashed) | Manual | Databases |
| **mTLS/Certs** | Transport | Private key | Auto possible | Service-to-service |
| **Kerberos** | App | Tickets | Auto (24h) | Enterprise SSO |
| **SSH Keys** | App | Private key | Manual | Server access |
| **OAuth/OIDC** | App (HTTP) | Tokens | Auto (short-lived) | APIs, web apps |
| **SASL/OAUTHBEARER** | App | OAuth tokens | Auto | Kafka, modern systems |
| **Cloud IAM** | App | IAM tokens | Auto (15 min) | Cloud databases |
| **SPIFFE** | Transport | X.509-SVID | Auto (hours) | Zero Trust workloads |
| **IPsec/WireGuard** | Network | Keys/PSK | Manual/Auto | VPN, network security |

### Where SPIFFE Fits In

```
┌─────────────────────────────────────────────────────────────────┐
│  SPIFFE can integrate with many of these!                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  • Database mTLS: Use X.509-SVID as client certificate          │
│  • Kafka: SASL/OAUTHBEARER with JWT-SVID                        │
│  • Cloud IAM: Federate JWT-SVID → AWS STS AssumeRoleWithWebIdentity
│  • Vault: Use SPIFFE auth method                                │
│  • Service mesh: Automatic mTLS between all services            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## SPIFFE/SPIRE Authentication: mTLS vs JWT-SVID

A common question: **Is mTLS the authentication method in SPIFFE/SPIRE?**

The answer: **mTLS is ONE of the authentication methods**, but not the only one. SPIFFE provides identity, and that identity can be used in multiple ways.

### Two Types of SVIDs

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SPIFFE Identity Documents (SVIDs)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                            SPIRE Server                                      │
│                                 │                                            │
│                    Issues SVIDs to workloads                                 │
│                                 │                                            │
│              ┌──────────────────┴──────────────────┐                        │
│              ▼                                     ▼                        │
│   ┌─────────────────────────┐         ┌─────────────────────────┐          │
│   │      X.509-SVID         │         │       JWT-SVID          │          │
│   │   (Certificate)         │         │      (JWT Token)        │          │
│   ├─────────────────────────┤         ├─────────────────────────┤          │
│   │                         │         │                         │          │
│   │  Used for: mTLS         │         │  Used for: HTTP APIs    │          │
│   │                         │         │  (Bearer tokens)        │          │
│   │  Layer: Transport (L5)  │         │  Layer: Application (L7)│          │
│   │                         │         │                         │          │
│   │  ┌───────────────────┐  │         │  ┌───────────────────┐  │          │
│   │  │ CN: spiffe://...  │  │         │  │ sub: spiffe://... │  │          │
│   │  │ SAN: spiffe://... │  │         │  │ aud: [...]        │  │          │
│   │  │ Issuer: SPIRE CA  │  │         │  │ exp: 1234567890   │  │          │
│   │  └───────────────────┘  │         │  └───────────────────┘  │          │
│   │                         │         │                         │          │
│   └─────────────────────────┘         └─────────────────────────┘          │
│              │                                     │                        │
│              ▼                                     ▼                        │
│   ┌─────────────────────────┐         ┌─────────────────────────┐          │
│   │  Service A ══mTLS══► B  │         │  App ──Bearer Token──►  │          │
│   │  (certificate auth)     │         │  API (JWT validation)   │          │
│   └─────────────────────────┘         └─────────────────────────┘          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### SPIFFE-Enabled Authentication Options

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              SPIFFE-Enabled Authentication Options                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Option 1: mTLS (using X.509-SVID)                                         │
│   ─────────────────────────────────                                         │
│                                                                              │
│   ┌─────────────┐                           ┌─────────────┐                 │
│   │  Service A  │═══════════════════════════│  Service B  │                 │
│   │             │      mTLS connection      │             │                 │
│   │  X.509-SVID │◄─────────────────────────►│  X.509-SVID │                 │
│   │  (client)   │  Both present certs       │  (server)   │                 │
│   └─────────────┘                           └─────────────┘                 │
│                                                                              │
│   ✅ Authentication at Transport Layer                                       │
│   ✅ Identity verified BEFORE any data exchanged                            │
│   ✅ Encrypted channel                                                       │
│                                                                              │
│   ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│   Option 2: JWT-SVID (Bearer Token)                                         │
│   ─────────────────────────────────                                         │
│                                                                              │
│   ┌─────────────┐                           ┌─────────────┐                 │
│   │  Service A  │──── TLS (server only) ───►│  Service B  │                 │
│   │             │                           │             │                 │
│   │  JWT-SVID   │  GET /api/data            │  Validates  │                 │
│   │  in header  │  Authorization: Bearer... │  JWT-SVID   │                 │
│   └─────────────┘                           └─────────────┘                 │
│                                                                              │
│   ✅ Authentication at Application Layer                                     │
│   ✅ Works with existing HTTP infrastructure                                │
│   ✅ Compatible with load balancers, proxies                                │
│   ✅ Can federate with OIDC systems (via OIDC Discovery Provider)           │
│                                                                              │
│   ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│   Option 3: Both (Defense in Depth)                                         │
│   ─────────────────────────────────                                         │
│                                                                              │
│   ┌─────────────┐                           ┌─────────────┐                 │
│   │  Service A  │══════════════════════════►│  Service B  │                 │
│   │             │      mTLS connection      │             │                 │
│   │  X.509-SVID │  + JWT-SVID in header     │  Validates  │                 │
│   │  + JWT-SVID │  (double verification)    │  both!      │                 │
│   └─────────────┘                           └─────────────┘                 │
│                                                                              │
│   ✅ Network identity (mTLS) + Application identity (JWT)                   │
│   ✅ Even if TLS is terminated, JWT still valid                             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### When to Use Which?

| Scenario | Use X.509-SVID (mTLS) | Use JWT-SVID |
|----------|----------------------|--------------|
| Direct service-to-service | ✅ Preferred | ✅ Also works |
| Through load balancer | ⚠️ Complex (TLS termination) | ✅ Preferred |
| Through API gateway | ⚠️ Complex | ✅ Preferred |
| Non-HTTP protocols (gRPC, DB) | ✅ Preferred | ❌ Not applicable |
| Federate with AWS/GCP | ❌ Not directly | ✅ JWT-SVID → STS |
| Federate with Vault | ✅ SPIFFE auth method | ✅ JWT auth method |
| Zero Trust (highest security) | ✅ Preferred | ⚠️ Weaker (token can leak) |

### The Two Authentication Questions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   Two Different "Authentications"                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. How does a WORKLOAD authenticate TO SPIRE?                             │
│      (To receive an SVID)                                                   │
│                                                                              │
│      This is called "ATTESTATION"                                           │
│                                                                              │
│      ┌─────────────┐                           ┌─────────────┐              │
│      │  Workload   │ ──── "Who am I?" ────────►│ SPIRE Agent │              │
│      │  (Pod)      │                           │             │              │
│      │             │ ◄─── "You are spiffe://..│             │              │
│      │             │      Here's your SVID"   │             │              │
│      └─────────────┘                           └─────────────┘              │
│                                                                              │
│      Attestation methods:                                                    │
│      • Kubernetes: ServiceAccount token, namespace, pod name                │
│      • AWS: Instance metadata, IAM role                                     │
│      • Docker: Container ID, image hash                                     │
│      • Unix: Process ID, user ID                                            │
│                                                                              │
│   ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│   2. How does a WORKLOAD authenticate TO ANOTHER WORKLOAD?                  │
│      (Using the SVID)                                                       │
│                                                                              │
│      ┌─────────────┐                           ┌─────────────┐              │
│      │  Service A  │ ──── Present SVID ───────►│  Service B  │              │
│      │  (has SVID) │                           │  (has SVID) │              │
│      │             │ ◄─── Validates SVID ──────│             │              │
│      └─────────────┘                           └─────────────┘              │
│                                                                              │
│      Authentication methods:                                                 │
│      • mTLS (using X.509-SVID)                                              │
│      • JWT Bearer token (using JWT-SVID)                                    │
│      • Both                                                                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Summary: SPIFFE Identity vs Authentication Method

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                  │
│   SPIFFE/SPIRE = Identity Framework                             │
│                                                                  │
│   mTLS = One way to USE that identity (via X.509-SVID)          │
│   JWT  = Another way to USE that identity (via JWT-SVID)        │
│                                                                  │
│   ───────────────────────────────────────────────────────────   │
│                                                                  │
│   Think of it like a driver's license:                          │
│                                                                  │
│   SPIFFE = The DMV that issues your license                     │
│   X.509-SVID = Physical card you show at a bar (mTLS)           │
│   JWT-SVID = Digital ID you show in an app (token auth)         │
│                                                                  │
│   Same identity, different ways to present it!                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Why This Matters

1. **OIDC tokens cannot do mTLS** - they're application-layer constructs, not certificates
2. **SPIFFE bridges the gap** - provides certificate-based identity for workloads
3. **SPIRE OIDC Discovery Provider** - makes SPIFFE identities consumable by OIDC-aware systems
4. **Defense in depth** - you can use both (OIDC for user identity, SPIFFE for workload identity)
