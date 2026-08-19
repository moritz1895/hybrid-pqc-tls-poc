package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc;

import static org.assertj.core.api.Assertions.assertThat;

import ms.rohde.hybridpqctlspoc.adapters.outbound.pki.bc.BcSelfSignedEcdsaCertificateIssuer;
import ms.rohde.hybridpqctlspoc.core.domain.CryptoBackendVariant;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsContexts;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;
import ms.rohde.hybridpqctlspoc.core.domain.NegotiatedTlsParameters;
import ms.rohde.hybridpqctlspoc.core.domain.TlsHandshakeOutcome;
import org.junit.jupiter.api.Test;

/**
 * End-to-end proof that the software crypto backend and the loopback
 * handshake executor together perform a genuine TLS 1.3 handshake that
 * negotiates the {@code X25519MLKEM768} hybrid post-quantum group on both
 * the server's and the client's side, and that application data actually
 * flows across the connection. This is the single most important test in
 * this project: it demonstrates the hybrid PQC handshake actually happens,
 * not merely that the code compiles.
 */
class HybridPqcTlsSoftwareBackendEndToEndTest {

    private static final String EXPECTED_HYBRID_GROUP = "X25519MLKEM768";

    private final BcSelfSignedEcdsaCertificateIssuer certificateIssuer = new BcSelfSignedEcdsaCertificateIssuer();
    private final BcSoftwareHybridPqcTlsCryptoBackend cryptoBackend = new BcSoftwareHybridPqcTlsCryptoBackend();
    private final BcLoopbackHybridPqcTlsHandshakeExecutor handshakeExecutor = new BcLoopbackHybridPqcTlsHandshakeExecutor();

    @Test
    void variant_givenSoftwareBackend_thenReturnsSoftware() {
        assertThat(cryptoBackend.variant()).isEqualTo(CryptoBackendVariant.SOFTWARE);
    }

    @Test
    void execute_givenSoftwareBackend_thenNegotiatesHybridPqcGroupOnBothSidesAndConfirmsApplicationData() {
        IssuedServerCertificate issuedServerCertificate = certificateIssuer.issue();
        HybridPqcTlsContexts contexts = cryptoBackend.buildContexts(issuedServerCertificate);

        TlsHandshakeOutcome outcome = handshakeExecutor.execute(contexts, cryptoBackend.variant());

        assertThat(outcome.applicationDataConfirmed()).isTrue();
        assertThat(outcome.backendVariant()).isEqualTo(CryptoBackendVariant.SOFTWARE);

        assertHybridGroupNegotiated(outcome.serverView());
        assertHybridGroupNegotiated(outcome.clientView());
    }

    private static void assertHybridGroupNegotiated(NegotiatedTlsParameters parameters) {
        assertThat(parameters.protocolVersion()).isEqualTo("TLSv1.3");
        assertThat(parameters.negotiatedGroup()).isEqualTo(EXPECTED_HYBRID_GROUP);
        assertThat(parameters.hybridPqcGroup()).isTrue();
    }
}
