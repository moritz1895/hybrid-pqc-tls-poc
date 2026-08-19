package ms.rohde.hybridpqctlspoc.adapters.outbound.pki.bc;

/**
 * Thrown when {@link BcSelfSignedEcdsaCertificateIssuer} fails to generate
 * the ephemeral demo key pair or self-signed certificate.
 */
public final class CertificateIssuanceException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    CertificateIssuanceException(String message, Throwable cause) {
        super(message, cause);
    }
}
