package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * Builds the server-side and client-side {@link SSLContext} instances shared
 * by every {@link ms.rohde.hybridpqctlspoc.ports.outbound.HybridPqcTlsCryptoBackend}
 * implementation: a {@link BouncyCastleJsseProvider} instance supplies the
 * {@code "TLS"} algorithm, and an in-memory {@link KeyStore} built from the
 * given {@link IssuedServerCertificate} supplies the server's identity (the
 * server context) and the client's trust anchor (the client context). Only
 * the {@link BouncyCastleJsseProvider} instance - and, transitively, the
 * {@code org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider} it was
 * built with - differs between the software and IBM-CCA backends.
 *
 * <p>The {@link KeyManagerFactory} and {@link TrustManagerFactory} are
 * requested from the given {@link BouncyCastleJsseProvider} instance itself
 * ({@code "X509"} / {@code "PKIX"}), not from the JDK's default provider
 * search. BCJSSE's TLS 1.3 credential selection queries the {@code
 * X509ExtendedKeyManager} with composite key-type strings such as {@code
 * "EC/secp256r1"} (algorithm plus required named group -
 * {@code SignatureSchemeInfo.getKeyType13()} in bc-java). The JDK's own
 * {@code sun.security.ssl.SunX509KeyManagerImpl} does not recognise that
 * composite format and returns no aliases for it, silently failing every
 * signature scheme and making every TLS 1.3 cipher suite unselectable with
 * {@code handshake_failure(40)} - confirmed by enabling {@code
 * java.util.logging} FINEST output for {@code org.bouncycastle.jsse.provider},
 * which showed "found no credentials for signature scheme ... (keyType
 * 'EC/secp256r1')" for every offered scheme even though the key store
 * contains a matching EC key. BC's own {@code KeyManagerFactory.X509} /
 * {@code TrustManagerFactory.PKIX} implementations (registered by {@link
 * BouncyCastleJsseProvider}) build a {@code ProvX509KeyManager} that
 * understands this composite convention natively, which resolves the issue.
 */
public final class HybridPqcSslContexts {

    private static final String KEY_STORE_TYPE = "PKCS12";
    private static final String KEY_ALIAS = "hybrid-pqc-tls-poc-demo";
    private static final char[] KEY_PASSWORD = "hybrid-pqc-tls-poc".toCharArray();
    private static final String KEY_MANAGER_FACTORY_ALGORITHM = "X509";
    private static final String TRUST_MANAGER_FACTORY_ALGORITHM = "PKIX";

    private HybridPqcSslContexts() {}

    public static SSLContext buildServerContext(
            BouncyCastleJsseProvider bcJsseProvider, IssuedServerCertificate issuedServerCertificate)
            throws GeneralSecurityException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(null, KEY_PASSWORD);
            keyStore.setKeyEntry(
                    KEY_ALIAS,
                    issuedServerCertificate.privateKey(),
                    KEY_PASSWORD,
                    new Certificate[] {issuedServerCertificate.certificate()});

            KeyManagerFactory keyManagerFactory =
                    KeyManagerFactory.getInstance(KEY_MANAGER_FACTORY_ALGORITHM, bcJsseProvider);
            keyManagerFactory.init(keyStore, KEY_PASSWORD);

            SSLContext sslContext = SSLContext.getInstance("TLS", bcJsseProvider);
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            return sslContext;
        } catch (IOException e) {
            throw new GeneralSecurityException("Failed to build the server key store", e);
        }
    }

    public static SSLContext buildClientContext(
            BouncyCastleJsseProvider bcJsseProvider, IssuedServerCertificate issuedServerCertificate)
            throws GeneralSecurityException {
        try {
            KeyStore trustStore = KeyStore.getInstance(KEY_STORE_TYPE);
            trustStore.load(null, KEY_PASSWORD);
            trustStore.setCertificateEntry(KEY_ALIAS, issuedServerCertificate.certificate());

            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TRUST_MANAGER_FACTORY_ALGORITHM, bcJsseProvider);
            trustManagerFactory.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS", bcJsseProvider);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
            return sslContext;
        } catch (IOException e) {
            throw new GeneralSecurityException("Failed to build the client trust store", e);
        }
    }
}
