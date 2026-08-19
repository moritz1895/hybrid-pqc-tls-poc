package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.cert.CertificateException;
import javax.net.ssl.SSLHandshakeException;
import ms.rohde.hybridpqctlspoc.adapters.outbound.pki.bc.BcSelfSignedEcdsaCertificateIssuer;
import ms.rohde.hybridpqctlspoc.core.domain.CryptoBackendVariant;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsContexts;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;
import org.junit.jupiter.api.Test;

/**
 * Proves spec use case 3.3 (certificate trust failure): if the client trusts
 * a different certificate than the one the server actually presents, the
 * loopback handshake must fail with a genuine certificate/trust error - not
 * hang, and not silently succeed.
 */
class HybridPqcTlsCertificateTrustFailureTest {

    private final BcSelfSignedEcdsaCertificateIssuer certificateIssuer = new BcSelfSignedEcdsaCertificateIssuer();
    private final BcSoftwareHybridPqcTlsCryptoBackend cryptoBackend = new BcSoftwareHybridPqcTlsCryptoBackend();
    private final BcLoopbackHybridPqcTlsHandshakeExecutor handshakeExecutor = new BcLoopbackHybridPqcTlsHandshakeExecutor();

    @Test
    void execute_givenClientTrustsDifferentCertificateThanServerPresents_thenFailsWithCertificateTrustError() {
        IssuedServerCertificate serverCertificate = certificateIssuer.issue();
        IssuedServerCertificate unrelatedCertificate = certificateIssuer.issue();
        assertThat(serverCertificate.certificate()).isNotEqualTo(unrelatedCertificate.certificate());

        // The server context presents serverCertificate; the client context is built from an
        // entirely unrelated certificate, so the client's trust store does not contain the
        // server's actual certificate.
        HybridPqcTlsContexts serverSideContexts = cryptoBackend.buildContexts(serverCertificate);
        HybridPqcTlsContexts mismatchedClientSideContexts = cryptoBackend.buildContexts(unrelatedCertificate);
        HybridPqcTlsContexts mismatchedContexts = new HybridPqcTlsContexts(
                serverSideContexts.serverContext(), mismatchedClientSideContexts.clientContext());

        assertThatThrownBy(() -> handshakeExecutor.execute(mismatchedContexts, CryptoBackendVariant.SOFTWARE))
                .isInstanceOf(HybridPqcTlsHandshakeIoException.class)
                .satisfies(exception -> assertThat(hasCertificateTrustCause(exception)).isTrue());
    }

    /**
     * Walks the full cause chain looking for a certificate/trust-related failure, rather than
     * asserting on one specific exception type - BCJSSE may wrap the underlying {@link
     * CertificateException} in an {@link SSLHandshakeException} or a raw {@code
     * org.bouncycastle.tls.TlsFatalAlert}, depending on which side (client or server) surfaces it
     * first.
     */
    private static boolean hasCertificateTrustCause(Throwable exception) {
        Throwable current = exception;
        while (current != null) {
            if (current instanceof CertificateException || current instanceof SSLHandshakeException) {
                return true;
            }
            String message = current.getMessage();
            if (message != null
                    && (message.toLowerCase(java.util.Locale.ROOT).contains("certificate")
                            || message.toLowerCase(java.util.Locale.ROOT).contains("trust")
                            || message.toLowerCase(java.util.Locale.ROOT).contains("unable to find valid "
                                    + "certification path"))) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}
