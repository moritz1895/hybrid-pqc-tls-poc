# Feature: Hybrid Post-Quantum TLS Demo

## Technical context

This project demonstrates a real TLS 1.3 handshake using the hybrid
post-quantum key-exchange group `X25519MLKEM768` (classical X25519 ECDH
combined with ML-KEM-768), running on Java 25.

The target runtime is IBM Semeru Runtime Certified Edition for z/OS,
version 25 (Java 25). The demo is also usable on any Java 25 distribution
(for example Eclipse Temurin 25 on Linux or Windows) for local development
and CI.

The JDK's built-in JSSE cannot be used for this: JEP 527 ("Post-Quantum
Hybrid Key Exchange for TLS 1.3"), which wires `X25519MLKEM768` and related
hybrid groups natively into `javax.net.ssl`, targets JDK 27 and is not part
of JDK 25. Java 25 provides only the underlying `javax.crypto.KEM` API and
the ML-KEM algorithm (JEP 496), not the TLS handshake integration.

The chosen approach is Bouncy Castle's `bctls-jdk18on` library, which ships
its own independent TLS 1.3 engine and a full JSSE-compatible security
`Provider` (`BouncyCastleJsseProvider`, "BCJSSE"). This provider already
supports the `X25519MLKEM768` hybrid group and is used through the standard
`javax.net.ssl` API (`SSLContext`, `SSLSocket`, `SSLServerSocket`) — no
custom JSSE provider needs to be developed.

An extensibility goal of this project is that, on real z/OS hardware (z16+
with a CEX8P crypto card), the ML-KEM part of the handshake should
eventually be able to run on IBM's `IBMJCECCA` JCE provider (hardware-backed
via ICSF/CCA), while the classical X25519 part continues to run in
software. This is achieved by configuring Bouncy Castle's
`JcaTlsCryptoProvider` (which builds the crypto backend for BCJSSE) with an
alternate JCA/JCE provider looked up at runtime by name
(`java.security.Security.getProvider("IBMJCECCA")`) — there is no
compile-time dependency on any IBM-proprietary jar, since none is publicly
available. If the provider is not registered — true for every environment
except real z/OS Semeru with ICSF — this fails fast with a clear error, and
never silently falls back to software.

The demo therefore needs two backend variants behind one outbound port: a
software-only variant (Bouncy Castle's own crypto for everything, runs
anywhere on JDK 25, and is the one actually exercised and tested in this
project's development environment) and an IBM-CCA-hardware variant (same
BCJSSE stack, with ML-KEM routed to `IBMJCECCA`; it compiles everywhere but
is only functionally verifiable on real z/OS with ICSF and a CEX8P card,
which is not available in this project's development or CI environment).

The demo performs a genuine local loopback TLS 1.3 handshake — a server
socket and a client socket on localhost — not just object construction. It
must observably prove that the hybrid group was actually negotiated:
protocol version, cipher suite, and negotiated named group, captured from
both the server's and the client's view of the completed handshake.

Authentication in the demo uses a classical, locally-generated self-signed
ECDSA P-256 server certificate. TLS 1.3 hybrid key exchange does not
require post-quantum certificates — only the key-agreement group is
hybrid. This matches current real-world practice and keeps the PoC's scope
on the key exchange, not on PQC certificate issuance.

This is a Hexagonal Architecture project (`ports/inbound`,
`ports/outbound`, `core/domain`, `core/app`, `adapters/inbound`,
`adapters/outbound`) with a thin Spring Boot `CommandLineRunner` as the
sole inbound adapter: one demo run at startup, then the process exits.

Selection between the two crypto backend variants happens via
configuration (a Spring profile). The default is the software variant; the
IBM-CCA variant is opt-in and is expected to fail fast with a clear error
outside real z/OS + ICSF hardware.

## 1. Feature summary

The application demonstrates, on demand, that a client and a server can
complete a genuine TLS 1.3 handshake negotiating the hybrid post-quantum
key-exchange group `X25519MLKEM768`. On startup, the application generates
a short-lived self-signed server certificate, starts a TLS server on a
local loopback socket, connects a TLS client to it, drives the handshake to
completion, and reports what was actually negotiated — proving the hybrid
post-quantum key exchange took place rather than merely being configured.
The demo supports two interchangeable ways of performing the post-quantum
part of the key exchange: entirely in software, or delegated to IBM's
hardware-backed cryptographic provider on z/OS.

## 2. Actors

- **Operator** — a developer or operator who runs the demo application
  (locally, in CI, or on z/OS) and reads its result from console output and
  process exit status.

## 3. Use cases

### 3.1 Run the hybrid PQC TLS handshake demo (software backend)

**Goal:** Prove that a TLS 1.3 handshake using the `X25519MLKEM768` hybrid
group succeeds end-to-end using a fully software-based crypto backend.

**Pre-conditions:**
- The application is started with no crypto-backend profile selected, or
  with the software profile explicitly selected.
- No external post-quantum hardware or provider is required.

**Main flow:**
1. The application starts and selects the software crypto backend (the
   default).
2. The application issues an ephemeral self-signed ECDSA P-256 server
   certificate and matching key pair for this run.
3. The application obtains a configured TLS crypto backend / `SSLContext`
   pair — one context configured to act as the server, one to act as the
   client — both restricted to TLS 1.3 and the `X25519MLKEM768` hybrid
   group, both backed entirely by Bouncy Castle's software crypto.
4. The application starts a TLS server socket bound to localhost using the
   server `SSLContext` and the issued certificate.
5. The application opens a TLS client socket to that server using the
   client `SSLContext`, configured to trust the issued certificate.
6. Server and client complete the TLS 1.3 handshake over the loopback
   connection.
7. The application captures, from both the server's and the client's view
   of the completed handshake, the negotiated protocol version, cipher
   suite, and negotiated named group.
8. The application reports the captured handshake details and confirms
   that the negotiated named group is `X25519MLKEM768` on both sides.
9. The application closes both sockets and exits successfully.

**Error flows:** see section 3.3 and 3.4, which apply regardless of which
backend variant is selected.

**Command shape:** `RunHybridPqcTlsDemo` — no input parameters (backend
variant comes from active configuration/profile, not from the command
itself).

**Result shape:** On success, returns the negotiated details for each side
(server and client) of the completed handshake — negotiated protocol
version, negotiated cipher suite, negotiated named group — together with
which crypto backend variant ran and whether the application-data
round-trip succeeded. On any failure, the use case throws an exception
naming the failed stage (certificate issuance, TLS context creation, or
handshake execution) instead of returning a result.

### 3.2 Run the hybrid PQC TLS handshake demo (IBM CCA hardware backend)

**Goal:** Prove the same hybrid handshake as 3.1, but with the ML-KEM part
of the key exchange delegated to IBM's `IBMJCECCA` JCE provider
(hardware-backed via ICSF/CCA), while the classical X25519 part continues
to run in software.

**Pre-conditions:**
- The application is started with the IBM-CCA crypto-backend profile
  explicitly selected (opt-in).
- Intended precondition for success: running on real z/OS Semeru Runtime
  with ICSF configured and a CEX8P crypto card available, so that
  `IBMJCECCA` is registered as a JCA/JCE security provider.

**Main flow:**
1. The application starts and selects the IBM-CCA crypto backend
   (explicit opt-in via configuration).
2. The application looks up the `IBMJCECCA` provider by name at runtime
   (`java.security.Security.getProvider("IBMJCECCA")`).
3. Provider found: the application configures the TLS crypto backend so
   that ML-KEM operations are routed to `IBMJCECCA` while X25519 operations
   continue in software, then proceeds exactly as in steps 2–9 of use case
   3.1 using this backend.
4. The application reports the captured handshake details, confirming
   `X25519MLKEM768` was negotiated with the ML-KEM portion executed on the
   hardware-backed provider.

**Error flows:**
- **IBM-CCA provider not registered** (the expected outcome in every
  environment except real z/OS with ICSF): the application fails fast
  during backend setup, before any handshake attempt, with a clear error
  identifying that `IBMJCECCA` is not registered as a security provider.
  It does not silently fall back to the software backend. The application
  exits with a failure indication.

**Command shape:** same as 3.1 — `RunHybridPqcTlsDemo`, no input
parameters.

**Result shape:** same as 3.1 on success. On the provider-not-registered
error flow, the use case is never invoked at all: constructing the
IBM-CCA crypto backend itself throws an exception naming the missing
`IBMJCECCA` provider as the cause, which fails Spring application context
startup before the demo run — and therefore the use case — ever begins.

### 3.3 Handshake fails due to certificate trust failure

**Goal:** Describe the demo's behavior if the client cannot establish
trust in the server's certificate.

**Pre-conditions:** A demo run (either backend variant) reaches the point
of attempting the handshake, but the client's trust configuration does not
accept the server's issued certificate (for example, a defect in how the
demo wires the issued certificate into the client's trust store).

**Main flow:** Not applicable — this is an error flow.

**Error flow:**
1. The client attempts the handshake against the server.
2. Certificate validation fails on the client side.
3. The handshake aborts before completion; no negotiated group is
   observed on the client side.
4. The application reports the demo outcome as failed, including the
   underlying trust error, and exits with a failure indication.

**Command shape:** same as 3.1.

**Result shape:** the use case throws an exception naming handshake
execution as the failed stage, wrapping the underlying certificate trust
error as the cause.

### 3.4 Handshake fails because the hybrid group is not supported by both peers

**Goal:** Describe the demo's behavior if server and client cannot agree on
the `X25519MLKEM768` hybrid group — included for completeness even though
this demo controls both endpoints and configures both consistently, so
this flow is not expected to occur in normal operation.

**Pre-conditions:** A demo run reaches the point of attempting the
handshake, but one side's `SSLContext` is not configured to offer or
accept the `X25519MLKEM768` group (for example, due to a configuration
defect).

**Main flow:** Not applicable — this is an error flow.

**Error flow:**
1. Server and client attempt the handshake.
2. The peers fail to negotiate a common supported group.
3. The handshake aborts before completion.
4. The application reports the demo outcome as failed, including the
   underlying negotiation error, and exits with a failure indication.

**Command shape:** same as 3.1.

**Result shape:** the use case throws an exception naming handshake
execution as the failed stage, describing the underlying
group-negotiation error.

## 4. Domain model additions

- **TlsHandshakeOutcome** (value object) — the negotiated details of one
  successfully completed demo handshake: the server's and the client's
  negotiated view, which crypto backend variant produced the contexts used
  for the handshake, and whether the application-data round-trip that
  proves the connection actually works was confirmed. Only ever produced
  on success — see the "Result shape" paragraphs in section 3 for how a
  failed attempt is represented instead.
- **NegotiatedTlsParameters** (value object) — the negotiated details
  observed from one side (server or client) of a completed handshake:
  protocol version, cipher suite name, negotiated named group, and whether
  that negotiated group is the hybrid post-quantum group.
- **CryptoBackendVariant** (value object) — identifies which of the two
  crypto backend variants (`SOFTWARE`, `IBM_CCA_HARDWARE`) is active for a
  given demo run.
- **IssuedServerCertificate** (value object) — the ephemeral self-signed
  ECDSA P-256 certificate and matching key pair issued for one demo run,
  used both to present it as the server's identity and to configure the
  client to trust it.
- **Domain rule:** a demo run is successful only if the negotiated named
  group observed on both the server side and the client side is
  `X25519MLKEM768`; any other negotiated group, or a failure to complete
  the handshake, causes the run to fail rather than produce a successful
  outcome.
- **Domain rule:** the IBM-CCA backend variant must never be silently
  substituted with the software variant; if the required provider is
  unavailable, the run fails, it does not degrade to a software-backed
  success.

## 5. Port additions

### Inbound

- **RunHybridPqcTlsDemoUseCase** — inbound port exposing the single
  operation that runs one full demo attempt (issue certificate, obtain
  configured backend, perform the loopback handshake, capture and return
  the outcome) and returns a `TlsHandshakeOutcome` on success. Invoked once
  at application startup by the sole inbound adapter (a Spring Boot
  `CommandLineRunner`).

### Outbound

The certificate issuance, TLS context construction, and handshake
execution concerns were consolidated into three separate outbound ports
during implementation, rather than the two originally sketched here — one
port each for issuing the certificate, building the crypto-backed context
pair, and driving the actual handshake, for cleaner separation of
concerns:

- **EphemeralServerCertificateIssuer** — outbound port for issuing the
  ephemeral self-signed ECDSA P-256 `IssuedServerCertificate` used to
  authenticate the server side of the demo handshake.
- **HybridPqcTlsCryptoBackend** — outbound port for obtaining a configured
  TLS crypto backend for the active `CryptoBackendVariant`: given the
  issued server certificate/key material, returns a matched pair of
  `SSLContext` instances (one configured to act as the TLS server, one as
  the TLS client), both restricted to TLS 1.3 and the `X25519MLKEM768`
  group, and reports which `CryptoBackendVariant` it provides. Two
  adapters implement this port — one backed entirely by Bouncy Castle
  software crypto, one routing the ML-KEM operations to the `IBMJCECCA`
  provider while keeping X25519 in software — selected via configuration.
  The IBM-CCA adapter fails fast with a clear error if `IBMJCECCA` is not
  registered as a security provider.
- **HybridPqcTlsHandshakeExecutor** — outbound port for performing the
  actual local loopback TLS handshake using a given context pair: binds
  the server socket, connects the client socket, exchanges application
  data to prove the connection works end-to-end, and captures and returns
  the negotiated `TlsHandshakeOutcome`.

## 6. Out of scope

- Post-quantum or hybrid certificates/signatures for server or client
  authentication — only the key-exchange group is hybrid.
- Client certificate authentication (mutual TLS).
- Any TLS group, cipher suite, or protocol version other than TLS 1.3 with
  `X25519MLKEM768`.
- Persisting, exporting, or externally serving handshake results — the
  demo reports its outcome via console output and process exit status
  only.
- Network exposure beyond the local loopback interface; the demo is not a
  long-running server.
- Automated functional verification of the IBM-CCA hardware backend in
  this project's development/CI environment, since no real z/OS + ICSF +
  CEX8P hardware is available there.
- Performance benchmarking or comparison between the software and
  hardware-backed backends.
- Key/certificate rotation, revocation, or any certificate lifecycle
  concern beyond issuing one ephemeral certificate per demo run.

## 7. Open questions

None — all points required to scope this feature are settled by the
technical context and the use cases above.
