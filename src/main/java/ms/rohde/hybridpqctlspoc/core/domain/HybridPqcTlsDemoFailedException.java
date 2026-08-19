package ms.rohde.hybridpqctlspoc.core.domain;

/**
 * Thrown when any stage of the hybrid PQC TLS demo fails: certificate
 * issuance, crypto context creation, or handshake execution. Every failure
 * originating from an outbound port is translated into this single domain
 * exception so callers of the use case only ever see one failure type.
 */
public class HybridPqcTlsDemoFailedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public HybridPqcTlsDemoFailedException(String message) {
        super(message);
    }

    public HybridPqcTlsDemoFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
