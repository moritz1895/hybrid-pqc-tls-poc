package ms.rohde.hybridpqctlspoc.core.domain;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * A freshly issued, self-signed ECDSA P-256 server certificate together with
 * its matching private key, generated for one demo run.
 */
@DomainValueObject
public record IssuedServerCertificate(X509Certificate certificate, PrivateKey privateKey) {

    public IssuedServerCertificate {
        Objects.requireNonNull(certificate, "certificate must not be null");
        Objects.requireNonNull(privateKey, "privateKey must not be null");
    }
}
