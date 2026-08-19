# Hybrid PQC TLS Handshake

How this project performs a genuine TLS 1.3 handshake negotiating the
`X25519MLKEM768` hybrid post-quantum key-exchange group on Java 25, and how
the negotiated group is proven rather than merely configured.

## Why not the JDK's built-in JSSE

JEP 527 ("Post-Quantum Hybrid Key Exchange for TLS 1.3") wires
`X25519MLKEM768` and related hybrid groups natively into `javax.net.ssl` /
`SunJSSE`. It targets **JDK 27**, not JDK 25. Java 25 provides the
underlying building blocks — the `javax.crypto.KEM` API and the ML-KEM
algorithm itself (JEP 496) — but no TLS 1.3 handshake integration for any
hybrid group. `SSLContext.getInstance("TLS")` against the platform default
provider on JDK 25 therefore cannot negotiate `X25519MLKEM768` at all.

## The crypto engine: Bouncy Castle's BCJSSE

This project uses `bctls-jdk18on`, Bouncy Castle's standalone, JDK-independent
TLS 1.3 stack, through its JSSE-compatible security `Provider`,
`org.bouncycastle.jsse.provider.BouncyCastleJsseProvider` ("BCJSSE"). BCJSSE
already implements `X25519MLKEM768` and is driven entirely through the
standard `javax.net.ssl` API (`SSLContext`, `SSLServerSocket`, `SSLSocket`) —
no custom JSSE provider is written by this project.

Three classes wire this up:

- **`BcSoftwareHybridPqcTlsCryptoBackend`**
  (`adapters/outbound/tls/bc`) — the default `HybridPqcTlsCryptoBackend`
  (`@Profile("!ibm-cca")`). Builds one process-wide `BouncyCastleJsseProvider`
  instance backed entirely by `BouncyCastleProvider` ("BC") and reuses it for
  every demo run.
- **`HybridPqcSslContexts`** (`adapters/outbound/tls/bc`) — the shared
  `SSLContext` builder used by both crypto-backend variants
  (`BcSoftwareHybridPqcTlsCryptoBackend` and
  `ms.rohde.hybridpqctlspoc.adapters.outbound.tls.icsf.IbmCcaHybridPqcTlsCryptoBackend`).
  Only the `BouncyCastleJsseProvider` instance passed in — and, transitively,
  the `JcaTlsCryptoProvider` it was built with — differs between the two.
- **`BcLoopbackHybridPqcTlsHandshakeExecutor`**
  (`adapters/outbound/tls/bc`) — performs the actual local loopback
  handshake: binds an `SSLServerSocket`, connects an `SSLSocket`, exchanges a
  fixed demo message and its echo, and captures the negotiated parameters
  from both sides.

## The bc-java #2252 pitfall and how it is avoided

BCJSSE's implicit configuration path — `new BouncyCastleJsseProvider()` or
`new BouncyCastleJsseProvider("default")` — lets its internal
`JcaTlsCryptoProvider` fall back to a plain JCA provider search for
cryptographic operations. On Java 25, that search can resolve ML-KEM to the
JDK's own (JEP 496) implementation instead of Bouncy Castle's, which silently
disables the `X25519MLKEM768` named group entirely. This is a confirmed,
documented bc-java pitfall (bcgit/bc-java issue #2252, "BCJSSE with Java 25
and Default Configuration Disables ML-KEM Named Groups").

Both `BcSoftwareHybridPqcTlsCryptoBackend` and `IbmCcaHybridPqcTlsCryptoBackend`
avoid this by never using the implicit constructor. Each explicitly builds a
`JcaTlsCryptoProvider`, pins it with `setProvider(bcProvider)` to
`BouncyCastleProvider`, and passes that pre-configured `JcaTlsCryptoProvider`
into `new BouncyCastleJsseProvider(false, cryptoProvider)`. The IBM-CCA
variant additionally calls `setAlternateProvider(...)` on the same
`JcaTlsCryptoProvider` (see
`docs/technical/ibmjcecca-integration-gap-analysis.md`). The `false`
constructor argument disables BCJSSE's FIPS-approved-only mode, which is not
relevant to this PoC.

## Why the restricted named-group list contains two groups

`BcLoopbackHybridPqcTlsHandshakeExecutor` restricts both the server socket
and the client socket to TLS 1.3 only and to a named-group allowlist via
`SSLParameters.setNamedGroups(String[])` (added to the JDK in JDK 20,
JDK-8288902; honoured by BCJSSE's `SSLParametersUtil`):

```java
private static final String[] RESTRICTED_PROTOCOLS = {"TLSv1.3"};
private static final String[] RESTRICTED_NAMED_GROUPS = {"X25519MLKEM768", "secp256r1"};
```

In TLS 1.3 the `supported_groups` extension serves two distinct purposes:
key-exchange group negotiation (`X25519MLKEM768`) and ECDSA signature-curve
negotiation for the peer certificate (`secp256r1`, matching the P-256 demo
certificate from `BcSelfSignedEcdsaCertificateIssuer`). Restricting the list
to the hybrid group alone made the handshake fail with
`handshake_failure(40)`, because the server's P-256 certificate had no usable
curve left for signing — confirmed against the oscerd/camel-pqc-tls reference
client, which offers both groups for the same reason. The key exchange still
negotiates `X25519MLKEM768` specifically: BCJSSE always prefers a hybrid PQC
group over a purely classical one when both are offered.

Because `secp256r1` is present in the allowlist, group *presence* in the
restricted list is not proof that the *hybrid* group was the one actually
negotiated — a classical-only fallback negotiating plain `secp256r1` key
exchange would also be technically valid under this configuration. This is
why `RunHybridPqcTlsDemoService.verifyHybridPqcGroupNegotiated(...)`
(`core/app`) explicitly checks the `hybridPqcGroup` flag on
`NegotiatedTlsParameters` for both `serverView` and `clientView`, and throws
`HybridPqcTlsDemoFailedException` if either side is `false` — not merely
that some named group was negotiated. `hybridPqcGroup` is computed in
`BcLoopbackHybridPqcTlsHandshakeExecutor.toNegotiatedParameters(...)` as
`HYBRID_GROUP_NAME.equals(negotiatedGroup)`, where `HYBRID_GROUP_NAME` is the
constant `"X25519MLKEM768"`.

## Reading the negotiated group: `NegotiatedGroupReader`

Neither `javax.net.ssl.SSLSession` nor BCJSSE's own extended
session/connection interfaces (`org.bouncycastle.jsse.BCSSLConnection`,
`org.bouncycastle.jsse.BCExtendedSSLSession`) expose the negotiated named
group — confirmed by inspecting the bc-java 1.85 sources of those interfaces
and of `org.bouncycastle.jsse.provider.ProvSSLSessionBase`, none of which
carry an accessor for it. BCJSSE's `java.util.logging` output does not log
the negotiated group on a successful handshake either (only configuration
warnings for unusable/unsupported configured groups).

The value is available through a genuinely public, typed API —
`SecurityParameters.getNegotiatedGroup()` on `org.bouncycastle.tls.TlsContext`
— but that context is reachable from the JSSE-facing `SSLSocket` only through
two package-private/protected implementation details of BCJSSE:

1. The `protocol` field on `org.bouncycastle.jsse.provider.ProvSSLSocketDirect`
   (the superclass of every concrete socket BCJSSE hands out), read via
   `Field.setAccessible(true)`.
2. The `protected abstract TlsContext getContext()` method on the public
   class `org.bouncycastle.tls.TlsProtocol`, invoked via
   `Method.setAccessible(true)`.

`NegotiatedGroupReader.read(SSLSocket)` walks the socket's class hierarchy to
locate the `protocol` field, walks the resulting object's class hierarchy to
locate and invoke `getContext()`, then calls the ordinary public API from
there: `tlsContext.getSecurityParametersConnection().getNegotiatedGroup()`
returns an `int`, resolved to a name via `NamedGroup.getName(int)`. No public
BCJSSE API exposes this value directly, so this reflective bridge is
necessary; everything past `getContext()` — `TlsContext`, `SecurityParameters`,
`NamedGroup` — is ordinary public Bouncy Castle API, not reflection. A
negative return from `getNegotiatedGroup()` (pre-TLS-1.3 connection, or no
group negotiated) is translated into `NegotiatedGroupUnavailableException`.

The Maven Surefire configuration in `pom.xml` opens the JDK internals this
reflection needs at test time (`--add-opens java.base/java.lang=ALL-UNNAMED`,
`java.util`, `java.lang.reflect`); production runs need no such flags because
the reflected members belong to Bouncy Castle's own classes, not the JDK's.

## Key manager / trust manager: BC's own algorithms, not `SunX509`

`HybridPqcSslContexts` requests `KeyManagerFactory` and `TrustManagerFactory`
instances from the given `BouncyCastleJsseProvider` explicitly, by algorithm
name and provider:

```java
KeyManagerFactory.getInstance("X509", bcJsseProvider);
TrustManagerFactory.getInstance("PKIX", bcJsseProvider);
```

This is deliberate, not the JDK-default `SunX509` / `PKIX` lookup. BCJSSE's
TLS 1.3 credential selection queries the `X509ExtendedKeyManager` with
composite key-type strings such as `"EC/secp256r1"` (algorithm plus required
named group — `SignatureSchemeInfo.getKeyType13()` in bc-java). The JDK's
own `sun.security.ssl.SunX509KeyManagerImpl` does not recognize this
composite format and returns no aliases for it, silently failing every
signature scheme and making every TLS 1.3 cipher suite unselectable with
`handshake_failure(40)` — even though the key store contains a matching EC
key. This was confirmed during implementation by enabling
`java.util.logging` `FINEST` output for `org.bouncycastle.jsse.provider`,
which showed `"found no credentials for signature scheme ... (keyType
'EC/secp256r1')"` for every offered scheme. Requesting `"X509"` /`"PKIX"`
from `BouncyCastleJsseProvider` instead yields BC's own
`ProvX509KeyManager`, which understands the composite convention natively
and resolves the issue.

## Related documentation

- `docs/technical/ibmjcecca-integration-gap-analysis.md` — the IBM-CCA
  crypto-backend variant referenced above, and what is confirmed vs. assumed
  about it.
- `docs/technical/jdk27-migration-notes.md` — what changes (and what does
  not) once JEP 527 ships as stable in JDK 27.
- `docs/features/hybrid-pqc-tls-demo.md` — the feature-level specification
  this handshake implements.
