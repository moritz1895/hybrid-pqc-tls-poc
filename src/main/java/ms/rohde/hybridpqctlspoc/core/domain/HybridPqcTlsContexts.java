package ms.rohde.hybridpqctlspoc.core.domain;

import java.util.Objects;
import javax.net.ssl.SSLContext;
import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * A matched pair of {@link SSLContext} instances configured to negotiate the
 * {@code X25519MLKEM768} hybrid post-quantum key-exchange group in a TLS 1.3
 * handshake: one acting as the server side, one as the client side.
 */
@DomainValueObject
public record HybridPqcTlsContexts(SSLContext serverContext, SSLContext clientContext) {

    public HybridPqcTlsContexts {
        Objects.requireNonNull(serverContext, "serverContext must not be null");
        Objects.requireNonNull(clientContext, "clientContext must not be null");
    }
}
