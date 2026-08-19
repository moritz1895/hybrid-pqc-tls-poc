package ms.rohde.hybridpqctlspoc.core.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.inOrder;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import ms.rohde.hybridpqctlspoc.core.domain.CryptoBackendVariant;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsContexts;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsDemoFailedException;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;
import ms.rohde.hybridpqctlspoc.core.domain.NegotiatedTlsParameters;
import ms.rohde.hybridpqctlspoc.core.domain.TlsHandshakeOutcome;
import ms.rohde.hybridpqctlspoc.ports.outbound.EphemeralServerCertificateIssuer;
import ms.rohde.hybridpqctlspoc.ports.outbound.HybridPqcTlsCryptoBackend;
import ms.rohde.hybridpqctlspoc.ports.outbound.HybridPqcTlsHandshakeExecutor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RunHybridPqcTlsDemoServiceTest {

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

    @Mock
    private EphemeralServerCertificateIssuer certificateIssuer;

    @Mock
    private HybridPqcTlsCryptoBackend cryptoBackend;

    @Mock
    private HybridPqcTlsHandshakeExecutor handshakeExecutor;

    private RunHybridPqcTlsDemoService service;

    private IssuedServerCertificate issuedServerCertificate;
    private HybridPqcTlsContexts contexts;
    private TlsHandshakeOutcome outcome;

    @BeforeEach
    void setUp() throws Exception {
        service = new RunHybridPqcTlsDemoService(certificateIssuer, cryptoBackend, handshakeExecutor);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(
                new ByteArrayInputStream(SELF_SIGNED_CERTIFICATE_PEM.getBytes(StandardCharsets.US_ASCII)));
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        issuedServerCertificate = new IssuedServerCertificate(certificate, privateKey);

        SSLContext sslContext = SSLContext.getDefault();
        contexts = new HybridPqcTlsContexts(sslContext, sslContext);

        NegotiatedTlsParameters parameters =
                new NegotiatedTlsParameters("TLSv1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768", true);
        outcome = new TlsHandshakeOutcome(parameters, parameters, CryptoBackendVariant.SOFTWARE, true);
    }

    private static NegotiatedTlsParameters parameters(String negotiatedGroup, boolean hybridPqcGroup) {
        return new NegotiatedTlsParameters("TLSv1.3", "TLS_AES_256_GCM_SHA384", negotiatedGroup, hybridPqcGroup);
    }

    @Test
    void run_givenAllPortsSucceed_thenReturnsOutcomeInOrder() {
        given(certificateIssuer.issue()).willReturn(issuedServerCertificate);
        given(cryptoBackend.buildContexts(issuedServerCertificate)).willReturn(contexts);
        given(cryptoBackend.variant()).willReturn(CryptoBackendVariant.SOFTWARE);
        given(handshakeExecutor.execute(contexts, CryptoBackendVariant.SOFTWARE)).willReturn(outcome);

        TlsHandshakeOutcome result = service.run();

        assertThat(result).isEqualTo(outcome);
        assertThat(result.serverView().hybridPqcGroup()).isTrue();
        assertThat(result.clientView().hybridPqcGroup()).isTrue();
        assertThat(result.backendVariant()).isEqualTo(CryptoBackendVariant.SOFTWARE);
        InOrder inOrder = inOrder(certificateIssuer, cryptoBackend, handshakeExecutor);
        inOrder.verify(certificateIssuer).issue();
        inOrder.verify(cryptoBackend).buildContexts(issuedServerCertificate);
        inOrder.verify(cryptoBackend).variant();
        inOrder.verify(handshakeExecutor).execute(contexts, CryptoBackendVariant.SOFTWARE);
    }

    @Test
    void run_givenIbmCcaHardwareVariant_thenReturnsOutcomeWithThatVariant() {
        TlsHandshakeOutcome ibmCcaOutcome = new TlsHandshakeOutcome(
                parameters("X25519MLKEM768", true),
                parameters("X25519MLKEM768", true),
                CryptoBackendVariant.IBM_CCA_HARDWARE,
                true);
        given(certificateIssuer.issue()).willReturn(issuedServerCertificate);
        given(cryptoBackend.buildContexts(issuedServerCertificate)).willReturn(contexts);
        given(cryptoBackend.variant()).willReturn(CryptoBackendVariant.IBM_CCA_HARDWARE);
        given(handshakeExecutor.execute(contexts, CryptoBackendVariant.IBM_CCA_HARDWARE))
                .willReturn(ibmCcaOutcome);

        TlsHandshakeOutcome result = service.run();

        assertThat(result.backendVariant()).isEqualTo(CryptoBackendVariant.IBM_CCA_HARDWARE);
        then(handshakeExecutor).should().execute(contexts, CryptoBackendVariant.IBM_CCA_HARDWARE);
    }

    @Test
    void run_givenClientNegotiatedNonHybridGroup_thenThrowsHybridPqcTlsDemoFailedException() {
        TlsHandshakeOutcome nonHybridOutcome = new TlsHandshakeOutcome(
                parameters("X25519MLKEM768", true),
                parameters("secp256r1", false),
                CryptoBackendVariant.SOFTWARE,
                true);
        given(certificateIssuer.issue()).willReturn(issuedServerCertificate);
        given(cryptoBackend.buildContexts(issuedServerCertificate)).willReturn(contexts);
        given(cryptoBackend.variant()).willReturn(CryptoBackendVariant.SOFTWARE);
        given(handshakeExecutor.execute(contexts, CryptoBackendVariant.SOFTWARE)).willReturn(nonHybridOutcome);

        assertThatThrownBy(() -> service.run())
                .isInstanceOf(HybridPqcTlsDemoFailedException.class)
                .hasMessageContaining("Hybrid PQC group was not negotiated")
                .hasMessageContaining("secp256r1");
    }

    @Test
    void run_givenServerNegotiatedNonHybridGroup_thenThrowsHybridPqcTlsDemoFailedException() {
        TlsHandshakeOutcome nonHybridOutcome = new TlsHandshakeOutcome(
                parameters("secp256r1", false),
                parameters("X25519MLKEM768", true),
                CryptoBackendVariant.SOFTWARE,
                true);
        given(certificateIssuer.issue()).willReturn(issuedServerCertificate);
        given(cryptoBackend.buildContexts(issuedServerCertificate)).willReturn(contexts);
        given(cryptoBackend.variant()).willReturn(CryptoBackendVariant.SOFTWARE);
        given(handshakeExecutor.execute(contexts, CryptoBackendVariant.SOFTWARE)).willReturn(nonHybridOutcome);

        assertThatThrownBy(() -> service.run())
                .isInstanceOf(HybridPqcTlsDemoFailedException.class)
                .hasMessageContaining("Hybrid PQC group was not negotiated")
                .hasMessageContaining("secp256r1");
    }

    @Test
    void run_givenBothSidesNegotiatedNonHybridGroup_thenThrowsHybridPqcTlsDemoFailedException() {
        TlsHandshakeOutcome nonHybridOutcome = new TlsHandshakeOutcome(
                parameters("secp256r1", false), parameters("secp256r1", false), CryptoBackendVariant.SOFTWARE, true);
        given(certificateIssuer.issue()).willReturn(issuedServerCertificate);
        given(cryptoBackend.buildContexts(issuedServerCertificate)).willReturn(contexts);
        given(cryptoBackend.variant()).willReturn(CryptoBackendVariant.SOFTWARE);
        given(handshakeExecutor.execute(contexts, CryptoBackendVariant.SOFTWARE)).willReturn(nonHybridOutcome);

        assertThatThrownBy(() -> service.run())
                .isInstanceOf(HybridPqcTlsDemoFailedException.class)
                .hasMessageContaining("Hybrid PQC group was not negotiated")
                .hasMessageContaining("secp256r1");
    }

    @Test
    void run_givenCertificateIssuerThrows_thenThrowsHybridPqcTlsDemoFailedExceptionWithCause() {
        RuntimeException cause = new RuntimeException("certificate issuance boom");
        given(certificateIssuer.issue()).willThrow(cause);

        assertThatThrownBy(() -> service.run())
                .isInstanceOf(HybridPqcTlsDemoFailedException.class)
                .hasCause(cause)
                .hasMessageContaining("Certificate issuance");

        then(cryptoBackend).shouldHaveNoInteractions();
        then(handshakeExecutor).shouldHaveNoInteractions();
    }

    @Test
    void run_givenCryptoBackendThrows_thenThrowsHybridPqcTlsDemoFailedExceptionWithCause() {
        RuntimeException cause = new RuntimeException("context creation boom");
        given(certificateIssuer.issue()).willReturn(issuedServerCertificate);
        given(cryptoBackend.buildContexts(issuedServerCertificate)).willThrow(cause);

        assertThatThrownBy(() -> service.run())
                .isInstanceOf(HybridPqcTlsDemoFailedException.class)
                .hasCause(cause)
                .hasMessageContaining("TLS context creation");

        then(handshakeExecutor).shouldHaveNoInteractions();
    }

    @Test
    void run_givenHandshakeExecutorThrows_thenThrowsHybridPqcTlsDemoFailedExceptionWithCause() {
        RuntimeException cause = new RuntimeException("handshake boom");
        given(certificateIssuer.issue()).willReturn(issuedServerCertificate);
        given(cryptoBackend.buildContexts(any())).willReturn(contexts);
        given(cryptoBackend.variant()).willReturn(CryptoBackendVariant.SOFTWARE);
        given(handshakeExecutor.execute(contexts, CryptoBackendVariant.SOFTWARE)).willThrow(cause);

        assertThatThrownBy(() -> service.run())
                .isInstanceOf(HybridPqcTlsDemoFailedException.class)
                .hasCause(cause)
                .hasMessageContaining("Handshake execution");
    }
}
