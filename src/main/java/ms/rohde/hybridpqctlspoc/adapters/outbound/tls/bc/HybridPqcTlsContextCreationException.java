package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc;

/**
 * Thrown when a {@link ms.rohde.hybridpqctlspoc.ports.outbound.HybridPqcTlsCryptoBackend}
 * fails to build the server-side/client-side {@link javax.net.ssl.SSLContext}
 * pair.
 */
public final class HybridPqcTlsContextCreationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public HybridPqcTlsContextCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}
