# IBMJCECCA Integration Gap Analysis

This document separates what is confirmed by this project's own code and
tests from what is assumed but unverified about the `IBMJCECCA` JCE
provider, for the `IbmCcaHybridPqcTlsCryptoBackend`
(`adapters/outbound/tls/icsf`) crypto-backend variant. No z/OS, ICSF, or
CEX8P hardware is available in this project's development or CI environment
— read every "confirmed" row below as confirmed against that constraint.

## What `IbmCcaHybridPqcTlsCryptoBackend` actually does

`IbmCcaHybridPqcTlsCryptoBackend` (`@Profile("ibm-cca")`, opt-in — the
default profile is `bc-software`) builds the same BCJSSE stack as
`BcSoftwareHybridPqcTlsCryptoBackend`, with one difference: its
`JcaTlsCryptoProvider` is configured with

```java
new JcaTlsCryptoProvider()
        .setProvider(bcProvider)
        .setAlternateProvider(ibmCcaProvider);
```

`setProvider(bcProvider)` keeps `BouncyCastleProvider` as the source for
everything else (in particular the classical X25519 half of the hybrid
group). `setAlternateProvider(ibmCcaProvider)` routes the ML-KEM operations
specifically to `ibmCcaProvider`. `ibmCcaProvider` is obtained purely by
runtime name lookup:

```java
Security.getProvider("IBMJCECCA")
```

There is deliberately **no compile-time dependency** on any IBM-proprietary
jar anywhere in `pom.xml` or `module-info.java` — none is publicly
available for this project's development environment. The provider is only
ever referenced by the string `"IBMJCECCA"` and the standard
`java.security.Provider` type.

**Confirmed** — by reading `IbmCcaHybridPqcTlsCryptoBackend` and
`IbmCcaHybridPqcTlsCryptoBackendTest`: if `Security.getProvider("IBMJCECCA")`
returns `null` — true in this project's development and CI environment —
the constructor throws `IbmCcaProviderUnavailableException` before any
`SSLContext` or handshake is attempted. There is no fallback path to the
software backend; the failure is fail-fast and explicit, matching the
domain rule in `docs/features/hybrid-pqc-tls-demo.md` ("the IBM-CCA backend
variant must never be silently substituted with the software variant").

## What is ASSUMED but NOT verified

**The exact JCE algorithm name `IBMJCECCA` registers ML-KEM-768 under is
unverified.** `JcaTlsCryptoProvider.setAlternateProvider(Provider)` routes
operations to the given provider by looking up algorithm names (e.g.
`"ML-KEM-768"`) through it via the standard JCA/JCE `Provider` service
lookup mechanism. This project assumes `IBMJCECCA` registers ML-KEM-768
under the JDK-standard name `"ML-KEM-768"`, per the JEP 496 naming
convention already used by the JDK's own `javax.crypto.KEM` provider
registrations. This assumption is **not confirmed**: the IBM documentation
page describing `IBMJCECCA`'s PQC algorithm support returned HTTP 403 to
automated access during development and could not be consulted. If
`IBMJCECCA` registers ML-KEM-768 under a different algorithm name (a
vendor-specific name, a different capitalization, or a different key-size
suffix convention), `JcaTlsCryptoProvider`'s alternate-provider lookup would
fail to find it, and the actual runtime failure mode on real hardware is
therefore also unverified — it could not be reproduced without the hardware
itself.

## What hardware/software is required for this path to ever function

- **z16 or later** IBM Z hardware.
- A **CEX8P** (Crypto Express8 with PKA support) crypto card, configured
  and available to the LPAR.
- **ICSF** (Integrated Cryptographic Service Facility) configured on z/OS,
  with the crypto card's ML-KEM support enabled.
- **IBM Semeru Runtime Certified Edition for z/OS**, the target JVM
  distribution named in `docs/features/hybrid-pqc-tls-demo.md`, with the
  `IBMJCECCA` provider registered in its `java.security` provider list (or
  registered programmatically before this backend runs).

None of these are present in this project's development or CI environment.

## What has NOT been tested

**This entire adapter has zero execution coverage beyond the
"provider absent" fail-fast unit test.**
`IbmCcaHybridPqcTlsCryptoBackendTest.constructor_givenIbmjceccaProviderNotRegistered_thenThrowsProviderUnavailableException`
is the only test exercising this class, and it only proves the negative
path: that construction fails correctly when `IBMJCECCA` is absent. It does
not — and, in this environment, cannot — exercise:

- Whether `Security.getProvider("IBMJCECCA")` actually returns a usable
  provider on real hardware.
- Whether `JcaTlsCryptoProvider.setAlternateProvider(...)` successfully
  routes an ML-KEM-768 operation to it (dependent on the unverified
  algorithm-name assumption above).
- Whether a full loopback handshake — server context and client context
  both built via `IbmCcaHybridPqcTlsCryptoBackend`, driven through
  `BcLoopbackHybridPqcTlsHandshakeExecutor` — actually negotiates
  `X25519MLKEM768` with the ML-KEM half of the computation running on the
  CEX8P card rather than in software.
- Performance, error handling, or behavior under any ICSF-specific failure
  mode (card unavailable at runtime, ICSF misconfiguration, key-size
  mismatch, etc.).

Do not read the presence of this adapter, its Javadoc, or its passing unit
test as evidence that the IBM-CCA path works on real z/OS hardware. It
demonstrates only that the code compiles, wires the extensibility seam
correctly (`JcaTlsCryptoProvider.setAlternateProvider`), and fails safely
when the provider is absent. Functional verification requires access to
real z16+/CEX8P/ICSF hardware, which this project does not have.

## Related documentation

- `docs/technical/hybrid-pqc-tls-handshake.md` — how the shared BCJSSE
  stack (`HybridPqcSslContexts`, both crypto-backend variants) is wired up.
- `docs/technical/jdk27-migration-notes.md` — how this extensibility seam
  is expected to evolve once JDK 27 ships JEP 527 natively.
