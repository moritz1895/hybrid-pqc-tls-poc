# hybrid-pqc-tls-poc

A proof of concept that a genuine TLS 1.3 handshake can negotiate the
hybrid post-quantum key-exchange group `X25519MLKEM768` today, on Java 25
running on IBM Semeru Runtime Certified Edition for z/OS — ahead of JDK 27,
which is the first JDK version to wire this group natively into its own TLS
stack. It exists for architects and platform engineers evaluating when and
how to adopt post-quantum TLS on z/OS, before the JDK itself supports it out
of the box: it demonstrates a real, verifiable handshake rather than a
configuration sketch, and it demonstrates an extensibility seam for routing
the post-quantum part of the key exchange to IBM's hardware-backed
cryptographic provider once that hardware is available.

## What this proves

On startup, the application issues an ephemeral self-signed server
certificate, opens a TLS server and a TLS client on a local loopback socket,
drives a real TLS 1.3 handshake to completion between them, and then
inspects what was actually negotiated on **both** sides — not merely what
was configured. Only if the negotiated named group is `X25519MLKEM768` on
both the server's and the client's view of the connection is the run
reported as a success. It also confirms an application-data round-trip
across the resulting connection, so the proof is that the connection works
end-to-end, not just that the handshake messages were exchanged.

Java 25 provides the underlying building blocks for hybrid post-quantum key
exchange (the `javax.crypto.KEM` API and the ML-KEM algorithm itself, JEP
496), but not the TLS 1.3 handshake integration — that is JEP 527 ("Post-
Quantum Hybrid Key Exchange for TLS 1.3"), targeted at **JDK 27**. On Java
25, this project instead uses Bouncy Castle's `bctls-jdk18on` library and
its JSSE-compatible security provider, `BouncyCastleJsseProvider` ("BCJSSE"),
which already implements `X25519MLKEM768` and is driven through the
standard `javax.net.ssl` API. See
[`docs/technical/hybrid-pqc-tls-handshake.md`](docs/technical/hybrid-pqc-tls-handshake.md)
for the full mechanics, including a documented Bouncy Castle pitfall this
project avoids and how the negotiated group is read back out of BCJSSE.

Authentication in the demo uses a classical, locally-generated self-signed
ECDSA P-256 server certificate — TLS 1.3 hybrid key exchange does not
require post-quantum certificates, only the key-agreement group is hybrid,
which matches current real-world practice.

## The two crypto backend variants

The demo supports two interchangeable ways of performing the post-quantum
part of the key exchange, selected by Spring profile:

- **Software backend (default)** — both the classical X25519 half and the
  ML-KEM half of the key exchange run entirely in software, through Bouncy
  Castle's own JCE provider. This is the variant actually exercised and
  verified in this project's development environment, in CI, and in the
  Docker image.
- **IBM-CCA hardware backend (`ibm-cca` profile, opt-in)** — the classical
  X25519 half still runs in software, but the ML-KEM half is routed to
  IBM's `IBMJCECCA` JCE provider (hardware-backed via ICSF/CCA). This
  backend compiles and fails fast correctly in every environment used
  during development, but its actual hardware-backed behavior has **not**
  been verified: it requires a real z16+ system with a CEX8P crypto card
  and ICSF configured, none of which is available here. If the `IBMJCECCA`
  provider is not registered — true everywhere except that real hardware —
  the application fails fast during startup with a clear error and never
  silently falls back to the software backend. See
  [`docs/technical/ibmjcecca-integration-gap-analysis.md`](docs/technical/ibmjcecca-integration-gap-analysis.md)
  for exactly what is confirmed versus assumed about this path.

## Features

- Genuine local loopback TLS 1.3 handshake negotiating `X25519MLKEM768`,
  driven through the standard `javax.net.ssl` API.
- Observable proof of what was negotiated, captured independently from both
  the server's and the client's view of the completed handshake, plus a
  confirmed application-data round-trip.
- Ephemeral self-signed ECDSA P-256 server certificate issuance, generated
  fresh for each demo run.
- Two selectable crypto backend variants — software-only and IBM-CCA
  hardware-backed — behind one outbound port, switched purely by
  configuration.
- Fail-fast behavior everywhere a required condition is not met (missing
  `IBMJCECCA` provider, non-hybrid negotiated group, handshake or trust
  failure) — never a silent degradation to a lesser guarantee.
- Hexagonal Architecture throughout, with a thin Spring Boot
  `CommandLineRunner` as the sole inbound adapter: one demo run at startup,
  then the process exits.

## Tech stack

- Java 25
- Spring Boot 4.1 (`spring-boot-starter`, `web-application-type: none` — no
  HTTP server; the CLI runner is the only inbound adapter)
- Bouncy Castle `bctls-jdk18on` / `bcprov-jdk18on` / `bcpkix-jdk18on` 1.85
  (TLS 1.3 engine, JCE provider, X.509 certificate building)
- Log4j2
- JSpecify (null-safety annotations)
- `ms.rohde:hexagonal-arch-*` (annotation vocabulary, ArchUnit rule suite,
  Spring component-scan integration)
- Maven

## Prerequisites

- **Java 25 JDK** on the local `PATH` (any distribution; the target runtime
  is IBM Semeru Runtime CE for z/OS, but Eclipse Temurin 25 or any other
  Java 25 distribution works for local development and CI).
- **Maven**, for building the jar.
- **Docker** and **Docker Compose**, only if running via `docker compose up`.
- Access to `ms.rohde:hexagonal-arch-*` on the internal Maven repository
  configured in `pom.xml` (`http://maven.home/releases`) — this dependency
  is not published to Maven Central.
- For the `ibm-cca` profile to actually succeed (not just fail fast
  correctly): a real IBM z16+ system with a CEX8P crypto card and ICSF
  configured, registering the `IBMJCECCA` provider. Not required to build,
  test, or run the software backend.

## Running locally

### Via Maven

```bash
mvn spring-boot:run
```

Runs the demo once, using the default software backend, and exits. To run
with the IBM-CCA profile instead (expected to fail fast outside real z/OS
hardware):

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=ibm-cca
```

### Via `run.sh`

```bash
./run.sh              # default (software) backend
./run.sh ibm-cca       # IBM-CCA hardware backend
./run.sh --rebuild            # force "mvn clean package -DskipTests" first
./run.sh --rebuild ibm-cca
```

`run.sh` verifies Java 25 is on `PATH`, builds the jar with Maven if none is
present in `target/` (or if `--rebuild` is passed), and runs it with
`java -jar`.

### Via Docker Compose

```bash
docker compose up --build
```

Builds the jar inside a `maven:3.9-eclipse-temurin-25` build stage, then
runs it in a minimal `eclipse-temurin:25-jre-alpine` runtime image as a
non-root user. **Docker only exercises the software backend** — the
`ibm-cca` profile requires real z/OS/ICSF/CEX8P hardware, which is not
something a container can provide.

### Reading the result

The application logs the negotiated protocol, cipher suite, and named group
for both the server's and the client's view, which backend variant ran,
whether the application-data round-trip was confirmed, and an overall
confirmation of whether the hybrid group was negotiated on both sides. It
exits with status `0` on success. On any failure, it logs the error and
exits with status `1`.

## Configuration

| Profile / parameter | Description | Default |
|---|---|---|
| *(no profile / any profile other than `ibm-cca`)* | Software crypto backend: both the classical X25519 and the ML-KEM part of the key exchange run in software via Bouncy Castle. | **Active by default** |
| `ibm-cca` | IBM-CCA hardware crypto backend: ML-KEM is routed to the `IBMJCECCA` JCE provider (ICSF/CCA hardware), X25519 continues in software. Opt-in. Fails application startup fast if `IBMJCECCA` is not registered as a security provider. | Not active |
| `spring.application.name` | Application name (`application.yml`). | `hybrid-pqc-tls-poc` |
| `spring.main.web-application-type` | Disables the embedded web server — this is a CLI demo, not a long-running server. | `none` |
| `spring.main.banner-mode` | Suppresses the Spring Boot startup banner. | `off` |

There are no other externally configurable parameters: the demo's behavior
(certificate subject, validity period, TLS protocol/group restriction) is
fixed by design to keep the PoC's scope narrow — see
[`docs/features/hybrid-pqc-tls-demo.md`](docs/features/hybrid-pqc-tls-demo.md),
section 6 ("Out of scope").

## Known limitations

- The IBM-CCA hardware backend is compiled and unit-tested only for its
  fail-fast path; its actual hardware-backed behavior on real z16+/CEX8P/
  ICSF hardware has never been exercised in this project's development or
  CI environment. See
  [`docs/technical/ibmjcecca-integration-gap-analysis.md`](docs/technical/ibmjcecca-integration-gap-analysis.md).
- Authentication is classical-only (self-signed ECDSA P-256); there are no
  post-quantum or hybrid certificates. This matches current real-world
  practice — TLS 1.3 hybrid key exchange does not require post-quantum
  certificates — but it means certificate authentication itself is out of
  scope for this PoC's post-quantum claims.
- The demo is a one-shot local loopback run, not a long-running server, and
  performs no persistence, export, or network exposure beyond loopback.

## Architecture

This project follows Hexagonal Architecture: pure domain value objects and
an application service in `core/domain` and `core/app`, port interfaces in
`ports/inbound` and `ports/outbound`, and framework-facing adapters —
including both crypto backend variants and the sole inbound adapter, a
Spring Boot `CommandLineRunner` — in `adapters/`. See
[`docs/features/hybrid-pqc-tls-demo.md`](docs/features/hybrid-pqc-tls-demo.md)
for the full domain model and use cases,
[`docs/technical/hybrid-pqc-tls-handshake.md`](docs/technical/hybrid-pqc-tls-handshake.md)
for how the handshake and BCJSSE integration work,
[`docs/technical/ibmjcecca-integration-gap-analysis.md`](docs/technical/ibmjcecca-integration-gap-analysis.md)
for the IBM-CCA backend's verified-vs-assumed boundary, and
[`docs/technical/jdk27-migration-notes.md`](docs/technical/jdk27-migration-notes.md)
for what changes once JDK 27 ships JEP 527 natively.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
