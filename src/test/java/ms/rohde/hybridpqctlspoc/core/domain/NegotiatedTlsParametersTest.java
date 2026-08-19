package ms.rohde.hybridpqctlspoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class NegotiatedTlsParametersTest {

    @Test
    void construct_givenValidValues_thenFieldsAreAccessible() {
        var parameters = new NegotiatedTlsParameters("TLSv1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768", true);

        assertThat(parameters.protocolVersion()).isEqualTo("TLSv1.3");
        assertThat(parameters.cipherSuite()).isEqualTo("TLS_AES_256_GCM_SHA384");
        assertThat(parameters.negotiatedGroup()).isEqualTo("X25519MLKEM768");
        assertThat(parameters.hybridPqcGroup()).isTrue();
    }

    @Test
    void construct_givenSameValues_thenEqualsAndHashCodeMatch() {
        var first = new NegotiatedTlsParameters("TLSv1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768", true);
        var second = new NegotiatedTlsParameters("TLSv1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768", true);

        assertThat(first).isEqualTo(second);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
    }

    @Test
    void construct_givenNullProtocolVersion_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new NegotiatedTlsParameters(null, "TLS_AES_256_GCM_SHA384", "X25519MLKEM768", true))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("protocolVersion");
    }

    @Test
    void construct_givenBlankProtocolVersion_thenThrowsIllegalArgumentException() {
        assertThatThrownBy(() -> new NegotiatedTlsParameters("  ", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768", true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("protocolVersion");
    }

    @Test
    void construct_givenNullCipherSuite_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new NegotiatedTlsParameters("TLSv1.3", null, "X25519MLKEM768", true))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("cipherSuite");
    }

    @Test
    void construct_givenBlankCipherSuite_thenThrowsIllegalArgumentException() {
        assertThatThrownBy(() -> new NegotiatedTlsParameters("TLSv1.3", " ", "X25519MLKEM768", true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cipherSuite");
    }

    @Test
    void construct_givenNullNegotiatedGroup_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new NegotiatedTlsParameters("TLSv1.3", "TLS_AES_256_GCM_SHA384", null, true))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("negotiatedGroup");
    }

    @Test
    void construct_givenBlankNegotiatedGroup_thenThrowsIllegalArgumentException() {
        assertThatThrownBy(() -> new NegotiatedTlsParameters("TLSv1.3", "TLS_AES_256_GCM_SHA384", "", true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("negotiatedGroup");
    }

    @Test
    void construct_givenNonHybridGroup_thenHybridPqcGroupIsFalse() {
        var parameters = new NegotiatedTlsParameters("TLSv1.3", "TLS_AES_256_GCM_SHA384", "secp256r1", false);

        assertThat(parameters.hybridPqcGroup()).isFalse();
    }
}
