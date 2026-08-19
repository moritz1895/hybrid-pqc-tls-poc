package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc;

/**
 * Thrown when {@link BcLoopbackHybridPqcTlsHandshakeExecutor} fails to bind
 * the loopback server socket, complete the TLS handshake, or exchange the
 * application-data round-trip.
 */
public final class HybridPqcTlsHandshakeIoException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    HybridPqcTlsHandshakeIoException(String message, Throwable cause) {
        super(message, cause);
    }
}
