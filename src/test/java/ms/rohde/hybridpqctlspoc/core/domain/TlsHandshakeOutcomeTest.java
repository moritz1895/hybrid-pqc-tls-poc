package ms.rohde.hybridpqctlspoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class TlsHandshakeOutcomeTest {

    private static NegotiatedTlsParameters parameters() {
        return new NegotiatedTlsParameters("TLSv1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768", true);
    }

    @Test
    void construct_givenValidViews_thenFieldsAreAccessible() {
        var serverView = parameters();
        var clientView = parameters();

        var outcome = new TlsHandshakeOutcome(serverView, clientView, CryptoBackendVariant.SOFTWARE, true);

        assertThat(outcome.serverView()).isEqualTo(serverView);
        assertThat(outcome.clientView()).isEqualTo(clientView);
        assertThat(outcome.backendVariant()).isEqualTo(CryptoBackendVariant.SOFTWARE);
        assertThat(outcome.applicationDataConfirmed()).isTrue();
    }

    @Test
    void construct_givenSameValues_thenEqualsAndHashCodeMatch() {
        var first = new TlsHandshakeOutcome(parameters(), parameters(), CryptoBackendVariant.SOFTWARE, true);
        var second = new TlsHandshakeOutcome(parameters(), parameters(), CryptoBackendVariant.SOFTWARE, true);

        assertThat(first).isEqualTo(second);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
    }

    @Test
    void construct_givenNullServerView_thenThrowsNullPointerException() {
        assertThatThrownBy(
                        () -> new TlsHandshakeOutcome(null, parameters(), CryptoBackendVariant.SOFTWARE, true))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("serverView");
    }

    @Test
    void construct_givenNullClientView_thenThrowsNullPointerException() {
        assertThatThrownBy(
                        () -> new TlsHandshakeOutcome(parameters(), null, CryptoBackendVariant.SOFTWARE, true))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("clientView");
    }

    @Test
    void construct_givenNullBackendVariant_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new TlsHandshakeOutcome(parameters(), parameters(), null, true))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("backendVariant");
    }

    @Test
    void construct_givenApplicationDataNotConfirmed_thenFieldReflectsFalse() {
        var outcome = new TlsHandshakeOutcome(parameters(), parameters(), CryptoBackendVariant.SOFTWARE, false);

        assertThat(outcome.applicationDataConfirmed()).isFalse();
    }

    @Test
    void construct_givenIbmCcaHardwareVariant_thenFieldReflectsVariant() {
        var outcome =
                new TlsHandshakeOutcome(parameters(), parameters(), CryptoBackendVariant.IBM_CCA_HARDWARE, true);

        assertThat(outcome.backendVariant()).isEqualTo(CryptoBackendVariant.IBM_CCA_HARDWARE);
    }
}
