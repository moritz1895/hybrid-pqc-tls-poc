# JDK 27 Migration Notes

This project targets Java 25, where JEP 527 ("Post-Quantum Hybrid Key
Exchange for TLS 1.3") is not yet available and Bouncy Castle's BCJSSE
provider is used instead (see
`docs/technical/hybrid-pqc-tls-handshake.md`). This note describes what
would change, and what would not, once JEP 527 ships as a stable JDK
feature in JDK 27 and IBM Semeru CE for z/OS adopts it.

## What would change

A new outbound adapter implementing `ports/outbound/HybridPqcTlsCryptoBackend`
would be added, using the JDK's own default `SSLContext` instead of BCJSSE:

```java
SSLContext.getInstance("TLS"); // platform default provider, no BouncyCastleJsseProvider
```

with the hybrid group restricted the same way
`BcLoopbackHybridPqcTlsHandshakeExecutor` restricts it today, but against
the native provider:

```java
sslParameters.setNamedGroups(new String[] {"X25519MLKEM768"});
```

The `secp256r1` addition documented in
`docs/technical/hybrid-pqc-tls-handshake.md` (needed to give BCJSSE's
credential selection a usable signature curve) would need to be
re-evaluated against JDK 27's own credential-selection behavior — it may or
may not exhibit the same requirement.

`NegotiatedGroupReader`'s reflective bridge into BCJSSE's package-private
`TlsProtocol`/`TlsContext` internals would not be needed for a JDK-native
adapter: `javax.net.ssl.SSLSession` under JEP 527 is expected to expose the
negotiated group through standard, public JSSE API, making that whole class
BCJSSE-specific and not reused by the new adapter.

The new adapter would be selected via a Spring profile exactly like the
existing `bc-software` / `ibm-cca` split — for example a `jdk-native`
profile — so all three variants could coexist behind the same
`HybridPqcTlsCryptoBackend` port, selected purely by configuration.

## What would NOT change

The hexagonal boundary means this is purely a new outbound adapter. None of
the following would change:

- Every port interface (`ports/inbound/RunHybridPqcTlsDemoUseCase`,
  `ports/outbound/HybridPqcTlsCryptoBackend`,
  `ports/outbound/HybridPqcTlsHandshakeExecutor`,
  `ports/outbound/EphemeralServerCertificateIssuer`).
- `core/domain` (`HybridPqcTlsContexts`, `NegotiatedTlsParameters`,
  `TlsHandshakeOutcome`, `IssuedServerCertificate`) — all framework-free and
  provider-agnostic already.
- `core/app` (`RunHybridPqcTlsDemoService`), including the
  `hybridPqcGroup`-flag enforcement that proves the hybrid group was
  actually negotiated, not merely offered.
- The CLI inbound adapter (`adapters/inbound/cli/HybridPqcTlsDemoRunner`).
- The certificate issuer (`adapters/outbound/pki/bc/BcSelfSignedEcdsaCertificateIssuer`)
  — TLS 1.3 hybrid key exchange still would not require post-quantum
  certificates, so the classical self-signed ECDSA P-256 certificate stays
  as-is.

The existing `BcSoftwareHybridPqcTlsCryptoBackend` and
`IbmCcaHybridPqcTlsCryptoBackend` adapters would also remain valid and
buildable unchanged: JDK 27 availability does not retire BCJSSE as an
option, it only makes a JDK-native alternative possible.
