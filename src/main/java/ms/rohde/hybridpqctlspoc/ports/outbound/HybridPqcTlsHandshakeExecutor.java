package ms.rohde.hybridpqctlspoc.ports.outbound;

import ms.rohde.hexagonalarch.annotations.InfrastructureServicePort;
import ms.rohde.hybridpqctlspoc.core.domain.CryptoBackendVariant;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsContexts;
import ms.rohde.hybridpqctlspoc.core.domain.TlsHandshakeOutcome;

/**
 * Performs a genuine local loopback TLS handshake: binds a server socket,
 * connects a client socket, exchanges at least one application-data message
 * to prove the connection actually works end-to-end, and captures the
 * negotiated parameters from both the server's and the client's point of
 * view.
 */
@InfrastructureServicePort
public interface HybridPqcTlsHandshakeExecutor {

    /**
     * Runs one local loopback TLS handshake and application-data exchange
     * using the given server and client contexts.
     *
     * @param contexts the server-side and client-side {@link
     *     javax.net.ssl.SSLContext} pair to use for the handshake
     * @param variant the crypto backend variant that produced {@code
     *     contexts}, recorded into the returned outcome since the executor
     *     has no other way of knowing which backend built them
     * @return the negotiated parameters observed from both sides, which
     *     backend variant was used, and whether the application-data
     *     round-trip succeeded
     */
    TlsHandshakeOutcome execute(HybridPqcTlsContexts contexts, CryptoBackendVariant variant);
}
