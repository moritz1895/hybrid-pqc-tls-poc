package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc;

/**
 * Thrown when {@link NegotiatedGroupReader} cannot determine the TLS named
 * group actually negotiated by a completed BCJSSE handshake.
 */
public final class NegotiatedGroupUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    NegotiatedGroupUnavailableException(String message) {
        super(message);
    }

    NegotiatedGroupUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
