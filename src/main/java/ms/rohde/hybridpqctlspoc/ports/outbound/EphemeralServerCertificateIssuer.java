package ms.rohde.hybridpqctlspoc.ports.outbound;

import ms.rohde.hexagonalarch.annotations.InfrastructureServicePort;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;

/**
 * Issues a fresh, locally-generated self-signed ECDSA P-256 server
 * certificate for one demo run.
 */
@InfrastructureServicePort
public interface EphemeralServerCertificateIssuer {

    /**
     * Generates a new self-signed ECDSA P-256 server certificate and its
     * matching private key.
     *
     * @return the issued certificate and key material
     */
    IssuedServerCertificate issue();
}
