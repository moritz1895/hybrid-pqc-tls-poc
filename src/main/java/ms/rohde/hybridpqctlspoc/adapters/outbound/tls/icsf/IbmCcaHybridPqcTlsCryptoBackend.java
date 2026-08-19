package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.icsf;

import jakarta.inject.Inject;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import javax.net.ssl.SSLContext;
import ms.rohde.hexagonalarch.annotations.InfrastructureServiceAdapter;
import ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc.HybridPqcSslContexts;
import ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc.HybridPqcTlsContextCreationException;
import ms.rohde.hybridpqctlspoc.core.domain.CryptoBackendVariant;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsContexts;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;
import ms.rohde.hybridpqctlspoc.ports.outbound.HybridPqcTlsCryptoBackend;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.springframework.context.annotation.Profile;

/**
 * Builds the hybrid-PQC-capable {@link SSLContext} pair the same way as
 * {@link ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc.BcSoftwareHybridPqcTlsCryptoBackend},
 * except that the ML-KEM part of the key exchange is routed to IBM's
 * hardware-backed {@code IBMJCECCA} JCE provider (ICSF/CCA, real z16+
 * hardware with a CEX8P crypto card) via {@link
 * JcaTlsCryptoProvider#setAlternateProvider(Provider)}, while the classical
 * X25519 part continues to run through {@link BouncyCastleProvider} in
 * software - the same split BCJSSE itself performs internally for any
 * hybrid group.
 *
 * <p>There is deliberately no compile-time dependency on any IBM-proprietary
 * jar: none is publicly available. The {@code IBMJCECCA} provider is looked
 * up by name at runtime via {@link Security#getProvider(String)}. If it is
 * not registered - true for every environment this project's development
 * and CI run in, since none has access to real z/OS/ICSF/CEX8P hardware -
 * this backend fails fast with {@link IbmCcaProviderUnavailableException}
 * and never silently falls back to the software backend.
 *
 * <p><b>Untested outside real z/OS + ICSF + CEX8P hardware.</b> This adapter
 * compiles and fails fast correctly in every environment available during
 * development, but its actual hardware-backed behaviour has never been
 * exercised. In particular, the assumption that {@code IBMJCECCA} registers
 * ML-KEM under the standard JCE algorithm name {@code ML-KEM-768} (the name
 * {@link JcaTlsCryptoProvider} would need to look up through the alternate
 * provider) is unverified - IBM's documentation page describing IBMJCECCA's
 * PQC algorithm support returned HTTP 403 to automated access during the
 * research for this project and could not be consulted.
 */
@InfrastructureServiceAdapter
@Profile("ibm-cca")
public final class IbmCcaHybridPqcTlsCryptoBackend implements HybridPqcTlsCryptoBackend {

    private static final String IBMJCECCA_PROVIDER_NAME = "IBMJCECCA";

    private final BouncyCastleJsseProvider bcJsseProvider;

    @Inject
    public IbmCcaHybridPqcTlsCryptoBackend() {
        this.bcJsseProvider = createBcJsseProviderWithIbmCcaAlternate();
    }

    @Override
    public HybridPqcTlsContexts buildContexts(IssuedServerCertificate issuedServerCertificate) {
        try {
            SSLContext serverContext = HybridPqcSslContexts.buildServerContext(bcJsseProvider, issuedServerCertificate);
            SSLContext clientContext = HybridPqcSslContexts.buildClientContext(bcJsseProvider, issuedServerCertificate);
            return new HybridPqcTlsContexts(serverContext, clientContext);
        } catch (GeneralSecurityException e) {
            throw new HybridPqcTlsContextCreationException(
                    "Failed to build hybrid PQC TLS contexts (IBM-CCA backend)", e);
        }
    }

    @Override
    public CryptoBackendVariant variant() {
        return CryptoBackendVariant.IBM_CCA_HARDWARE;
    }

    private static BouncyCastleJsseProvider createBcJsseProviderWithIbmCcaAlternate() {
        Provider ibmCcaProvider = Security.getProvider(IBMJCECCA_PROVIDER_NAME);
        if (ibmCcaProvider == null) {
            throw new IbmCcaProviderUnavailableException(
                    "The '" + IBMJCECCA_PROVIDER_NAME + "' security provider is not registered. This is expected "
                            + "on any environment other than real IBM z/OS with ICSF and a CEX8P crypto card - the "
                            + "'ibm-cca' profile is not supported here. Use the default software backend instead.");
        }

        BouncyCastleProvider bcProvider = registerBcProviderIdempotently();
        JcaTlsCryptoProvider cryptoProvider =
                new JcaTlsCryptoProvider().setProvider(bcProvider).setAlternateProvider(ibmCcaProvider);
        return new BouncyCastleJsseProvider(false, cryptoProvider);
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
}
