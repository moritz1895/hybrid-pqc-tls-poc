package ms.rohde.hybridpqctlspoc.core.domain;

import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * The outcome of one completed hybrid PQC TLS 1.3 demo handshake: the
 * negotiated parameters observed from both peers, which crypto backend
 * variant produced the contexts used for the handshake, and whether the
 * application-data round-trip that proves the connection actually works was
 * confirmed.
 */
@DomainValueObject
public record TlsHandshakeOutcome(
        NegotiatedTlsParameters serverView,
        NegotiatedTlsParameters clientView,
        CryptoBackendVariant backendVariant,
        boolean applicationDataConfirmed) {

    public TlsHandshakeOutcome {
        Objects.requireNonNull(serverView, "serverView must not be null");
        Objects.requireNonNull(clientView, "clientView must not be null");
        Objects.requireNonNull(backendVariant, "backendVariant must not be null");
    }
}
