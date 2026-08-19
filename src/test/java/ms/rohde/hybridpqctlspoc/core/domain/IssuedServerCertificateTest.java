package ms.rohde.hybridpqctlspoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class IssuedServerCertificateTest {

    private static final String SELF_SIGNED_CERTIFICATE_PEM =
            """
            -----BEGIN CERTIFICATE-----
            MIIBmDCCAT+gAwIBAgIUO+mhcuZRMhT/MJRc6yBystg39k0wCgYIKoZIzj0EAwIw
            IjEgMB4GA1UEAwwXaHlicmlkLXBxYy10bHMtcG9jLXRlc3QwHhcNMjYwODE5MDcy
            OTUwWhcNMzYwODE2MDcyOTUwWjAiMSAwHgYDVQQDDBdoeWJyaWQtcHFjLXRscy1w
            b2MtdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMaS52ew7LRPsqGmwRcN
            l73Nj7HTBSH18s7qjBF4wu/i91FVn7JHbQO0zvBFRFfPmWkX/hrZlETS4ooFPjUw
            yv2jUzBRMB0GA1UdDgQWBBRDApd/7DxjGbA40YJ3jcsHyvkulTAfBgNVHSMEGDAW
            gBRDApd/7DxjGbA40YJ3jcsHyvkulTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
            BAMCA0cAMEQCIHLOYTW7kB/4tzpJ4u0kARb81eMWwdseFfPJjQwBi0FuAiAoYjJQ
            qea7k0Pcv2yxGagHz/JHhQYlbVlVc6Gx8C/Rgg==
            -----END CERTIFICATE-----
            """;

    private X509Certificate certificate;
    private PrivateKey privateKey;

    @BeforeEach
    void setUp() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        certificate = (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(SELF_SIGNED_CERTIFICATE_PEM.getBytes(StandardCharsets.US_ASCII)));

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
    }

    @Test
    void construct_givenValidCertificateAndKey_thenFieldsAreAccessible() {
        var issued = new IssuedServerCertificate(certificate, privateKey);

        assertThat(issued.certificate()).isEqualTo(certificate);
        assertThat(issued.privateKey()).isEqualTo(privateKey);
    }

    @Test
    void construct_givenSameValues_thenEqualsAndHashCodeMatch() {
        var first = new IssuedServerCertificate(certificate, privateKey);
        var second = new IssuedServerCertificate(certificate, privateKey);

        assertThat(first).isEqualTo(second);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
    }

    @Test
    void construct_givenNullCertificate_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new IssuedServerCertificate(null, privateKey))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("certificate");
    }

    @Test
    void construct_givenNullPrivateKey_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new IssuedServerCertificate(certificate, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("privateKey");
    }
}
