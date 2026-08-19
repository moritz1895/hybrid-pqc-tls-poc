package ms.rohde.hybridpqctlspoc.adapters.outbound.pki.bc;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import jakarta.inject.Inject;
import ms.rohde.hexagonalarch.annotations.InfrastructureServiceAdapter;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;
import ms.rohde.hybridpqctlspoc.ports.outbound.EphemeralServerCertificateIssuer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.BigIntegers;

/**
 * Generates a fresh ECDSA P-256 key pair and a matching short-lived
 * self-signed X.509 certificate for one demo run, using Bouncy Castle's
 * {@link X509v3CertificateBuilder} (via bcpkix). TLS 1.3 hybrid post-quantum
 * key exchange does not require post-quantum certificates - only the
 * key-agreement group is hybrid - so a classical ECDSA certificate is
 * sufficient here.
 */
@InfrastructureServiceAdapter
public final class BcSelfSignedEcdsaCertificateIssuer implements EphemeralServerCertificateIssuer {

    private static final String SUBJECT_DN = "CN=hybrid-pqc-tls-poc-demo";
    private static final Duration VALIDITY = Duration.ofDays(1);

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Inject
    public BcSelfSignedEcdsaCertificateIssuer() {}

    @Override
    public IssuedServerCertificate issue() {
        try {
            KeyPair keyPair = generateEcKeyPair();
            X509Certificate certificate = buildSelfSignedCertificate(keyPair);
            return new IssuedServerCertificate(certificate, keyPair.getPrivate());
        } catch (GeneralSecurityException | OperatorCreationException e) {
            throw new CertificateIssuanceException("Failed to issue self-signed ECDSA demo certificate", e);
        }
    }

    private static KeyPair generateEcKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate buildSelfSignedCertificate(KeyPair keyPair)
            throws GeneralSecurityException, OperatorCreationException {
        Instant notBefore = Instant.now();
        Instant notAfter = notBefore.plus(VALIDITY);

        X500Name subject = new X500Name(SUBJECT_DN);
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                subject, randomSerialNumber(), Date.from(notBefore), Date.from(notAfter), subject, keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certificateBuilder.build(contentSigner));
    }

    private static BigInteger randomSerialNumber() {
        return BigIntegers.createRandomInRange(BigInteger.ONE, BigInteger.valueOf(Long.MAX_VALUE), new SecureRandom());
    }
}
