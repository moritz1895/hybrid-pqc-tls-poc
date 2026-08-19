package ms.rohde.hybridpqctlspoc.ports.outbound;

import ms.rohde.hexagonalarch.annotations.InfrastructureServicePort;
import ms.rohde.hybridpqctlspoc.core.domain.CryptoBackendVariant;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsContexts;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;

/**
 * Builds a matched pair of server-side and client-side {@link
 * javax.net.ssl.SSLContext} instances configured to negotiate the {@code
 * X25519MLKEM768} hybrid post-quantum key-exchange group in a TLS 1.3
 * handshake.
 *
 * <p>Concrete implementations may differ in which cryptographic provider
 * actually performs the ML-KEM operations — entirely in software, or
 * delegated to a hardware-backed provider — but every implementation must
 * always produce contexts that support the hybrid group.
 */
@InfrastructureServicePort
public interface HybridPqcTlsCryptoBackend {

    /**
     * Builds the server-side and client-side {@link javax.net.ssl.SSLContext}
     * pair for this demo run, authenticated by the given issued server
     * certificate.
     *
     * @param issuedServerCertificate the certificate and key material the
     *     server context presents, and the client context trusts
     * @return the matched pair of contexts
     */
    HybridPqcTlsContexts buildContexts(IssuedServerCertificate issuedServerCertificate);

    /**
     * Identifies which crypto backend variant this implementation is —
     * software-only or IBM-CCA-hardware-backed — so it can be reported as
     * part of the demo's outcome.
     *
     * @return the variant this implementation provides
     */
    CryptoBackendVariant variant();
}
