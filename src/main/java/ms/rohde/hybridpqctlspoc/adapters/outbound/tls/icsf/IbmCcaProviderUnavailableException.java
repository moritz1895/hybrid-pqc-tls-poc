package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.icsf;

/**
 * Thrown when the {@code IBMJCECCA} security provider is not registered at
 * runtime. Expected on every environment except a real IBM z/OS system with
 * ICSF and a CEX8P crypto card - this project's development and CI
 * environments included. {@link IbmCcaHybridPqcTlsCryptoBackend} never
 * silently falls back to a software implementation when this happens.
 */
public final class IbmCcaProviderUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    IbmCcaProviderUnavailableException(String message) {
        super(message);
    }
}
