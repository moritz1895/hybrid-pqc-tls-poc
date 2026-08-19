package ms.rohde.hybridpqctlspoc.ports.inbound;

import ms.rohde.hexagonalarch.annotations.DrivingPort;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsDemoFailedException;
import ms.rohde.hybridpqctlspoc.core.domain.TlsHandshakeOutcome;

/**
 * Runs one end-to-end demo of the hybrid PQC TLS 1.3 handshake and returns
 * the negotiated parameters from both sides.
 */
@DrivingPort
public interface RunHybridPqcTlsDemoUseCase {

    /**
     * Issues a fresh server certificate, builds a hybrid-PQC-capable TLS
     * context pair, performs a local loopback handshake, and returns the
     * resulting outcome.
     *
     * @return the outcome of the completed handshake
     * @throws HybridPqcTlsDemoFailedException if certificate issuance,
     *     context creation, or handshake execution fails
     */
    TlsHandshakeOutcome run();
}
