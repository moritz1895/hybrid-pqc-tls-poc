package ms.rohde.hybridpqctlspoc.core.domain;

import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * The TLS parameters negotiated in a completed handshake, as observed from
 * one side (server or client) of the connection.
 */
@DomainValueObject
public record NegotiatedTlsParameters(
        String protocolVersion, String cipherSuite, String negotiatedGroup, boolean hybridPqcGroup) {

    public NegotiatedTlsParameters {
        requireNonBlank(protocolVersion, "protocolVersion");
        requireNonBlank(cipherSuite, "cipherSuite");
        requireNonBlank(negotiatedGroup, "negotiatedGroup");
    }

    private static void requireNonBlank(String value, String fieldName) {
        Objects.requireNonNull(value, fieldName + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
    }
}
