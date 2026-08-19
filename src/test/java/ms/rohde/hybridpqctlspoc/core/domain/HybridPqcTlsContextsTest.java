package ms.rohde.hybridpqctlspoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HybridPqcTlsContextsTest {

    private SSLContext serverContext;
    private SSLContext clientContext;

    @BeforeEach
    void setUp() throws Exception {
        serverContext = SSLContext.getDefault();
        clientContext = SSLContext.getDefault();
    }

    @Test
    void construct_givenValidContexts_thenFieldsAreAccessible() {
        var contexts = new HybridPqcTlsContexts(serverContext, clientContext);

        assertThat(contexts.serverContext()).isEqualTo(serverContext);
        assertThat(contexts.clientContext()).isEqualTo(clientContext);
    }

    @Test
    void construct_givenSameValues_thenEqualsAndHashCodeMatch() {
        var first = new HybridPqcTlsContexts(serverContext, clientContext);
        var second = new HybridPqcTlsContexts(serverContext, clientContext);

        assertThat(first).isEqualTo(second);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
    }

    @Test
    void construct_givenNullServerContext_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new HybridPqcTlsContexts(null, clientContext))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("serverContext");
    }

    @Test
    void construct_givenNullClientContext_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new HybridPqcTlsContexts(serverContext, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("clientContext");
    }
}
