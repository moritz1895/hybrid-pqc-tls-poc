package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc;

import jakarta.inject.Inject;
import java.security.GeneralSecurityException;
import java.security.Security;
import javax.net.ssl.SSLContext;
import ms.rohde.hexagonalarch.annotations.InfrastructureServiceAdapter;
import ms.rohde.hybridpqctlspoc.core.domain.CryptoBackendVariant;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsContexts;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;
import ms.rohde.hybridpqctlspoc.ports.outbound.HybridPqcTlsCryptoBackend;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.springframework.context.annotation.Profile;

/**
 * Builds the hybrid-PQC-capable {@link SSLContext} pair entirely in
 * software, using Bouncy Castle's own JCE provider ({@link
 * BouncyCastleProvider}, "BC") as the source of all cryptographic
 * operations for BCJSSE's {@link JcaTlsCryptoProvider}. This is the default
 * backend and runs on any Java 25 distribution.
 *
 * <p>Both {@link BouncyCastleProvider} and {@link BouncyCastleJsseProvider}
 * are registered as JCA/JCE security providers idempotently. The actual
 * {@link SSLContext} instances are obtained from a locally constructed
 * {@link BouncyCastleJsseProvider} instance (not by provider-name lookup)
 * that wraps an explicitly configured {@link JcaTlsCryptoProvider} - never
 * via {@code new BouncyCastleJsseProvider("default")}. On Java 25, the
 * string-based "default" configuration lets BCJSSE fall back to a plain JCA
 * provider search that can pick up the JDK's own (JEP 496) ML-KEM
 * implementation for the KEM step, which disables the {@code
 * X25519MLKEM768} named group entirely (observed and confirmed via
 * bcgit/bc-java issue #2252, "BCJSSE with Java 25 and Default Configuration
 * Disables ML-KEM Named Groups"). Explicitly pinning the {@link
 * JcaTlsCryptoProvider} to {@link BouncyCastleProvider} avoids that pitfall.
 */
@InfrastructureServiceAdapter
@Profile("!ibm-cca")
public final class BcSoftwareHybridPqcTlsCryptoBackend implements HybridPqcTlsCryptoBackend {

    /**
     * Built once per JVM with an explicit, BC-backed {@link JcaTlsCryptoProvider} and reused
     * for every demo run - never {@code new BouncyCastleJsseProvider()} / {@code
     * new BouncyCastleJsseProvider("default")}, whose implicit provider search is the exact
     * Java-25 pitfall described in the class JavaDoc.
     */
    private static final BouncyCastleProvider BC_PROVIDER = registerBcProviderIdempotently();

    private static final BouncyCastleJsseProvider BCJSSE_PROVIDER = registerBcJsseProviderIdempotently(BC_PROVIDER);

    @Inject
    public BcSoftwareHybridPqcTlsCryptoBackend() {}

    @Override
    public HybridPqcTlsContexts buildContexts(IssuedServerCertificate issuedServerCertificate) {
        try {
            SSLContext serverContext =
                    HybridPqcSslContexts.buildServerContext(BCJSSE_PROVIDER, issuedServerCertificate);
            SSLContext clientContext =
                    HybridPqcSslContexts.buildClientContext(BCJSSE_PROVIDER, issuedServerCertificate);
            return new HybridPqcTlsContexts(serverContext, clientContext);
        } catch (GeneralSecurityException e) {
            throw new HybridPqcTlsContextCreationException(
                    "Failed to build hybrid PQC TLS contexts (software backend)", e);
        }
    }

    @Override
    public CryptoBackendVariant variant() {
        return CryptoBackendVariant.SOFTWARE;
    }

    private static BouncyCastleProvider registerBcProviderIdempotently() {
        BouncyCastleProvider existing = (BouncyCastleProvider) Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (existing != null) {
            return existing;
        }
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        return provider;
    }

    private static BouncyCastleJsseProvider registerBcJsseProviderIdempotently(BouncyCastleProvider bcProvider) {
        JcaTlsCryptoProvider cryptoProvider = new JcaTlsCryptoProvider().setProvider(bcProvider);
        BouncyCastleJsseProvider provider = new BouncyCastleJsseProvider(false, cryptoProvider);
        if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null) {
            Security.addProvider(provider);
        }
        return provider;
    }
}
