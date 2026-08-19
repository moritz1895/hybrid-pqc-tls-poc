package ms.rohde.hybridpqctlspoc.adapters.outbound.pki.bc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;
import org.junit.jupiter.api.Test;

class BcSelfSignedEcdsaCertificateIssuerTest {

    private final BcSelfSignedEcdsaCertificateIssuer issuer = new BcSelfSignedEcdsaCertificateIssuer();

    @Test
    void issue_givenNoInput_thenReturnsSelfSignedCertificateWithMatchingEcKeyPair() {
        IssuedServerCertificate issued = issuer.issue();

        X509Certificate certificate = issued.certificate();
        assertThat(certificate.getSubjectX500Principal()).isEqualTo(certificate.getIssuerX500Principal());

        PublicKey publicKey = certificate.getPublicKey();
        assertThat(publicKey).isInstanceOf(ECPublicKey.class);

        assertThatCode(() -> certificate.verify(publicKey)).doesNotThrowAnyException();
    }

    @Test
    void issue_givenNoInput_thenCertificateIsCurrentlyValid() {
        X509Certificate certificate = issuer.issue().certificate();

        assertThatCode(certificate::checkValidity).doesNotThrowAnyException();
    }

    @Test
    void issue_givenTwoCalls_thenGeneratesFreshKeyPairEachTime() {
        IssuedServerCertificate first = issuer.issue();
        IssuedServerCertificate second = issuer.issue();

        assertThat(first.certificate().getSerialNumber()).isNotEqualTo(second.certificate().getSerialNumber());
        assertThat(first.privateKey()).isNotEqualTo(second.privateKey());
    }
}
