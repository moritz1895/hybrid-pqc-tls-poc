package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import ms.rohde.hybridpqctlspoc.adapters.outbound.pki.bc.BcSelfSignedEcdsaCertificateIssuer;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsContexts;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Proves spec use case 3.4 (group negotiation failure): if the client and
 * server offer no overlapping TLS named group at all, the handshake must
 * fail with a clear negotiation error - not hang, and not silently fall back
 * to a group neither side actually wanted.
 *
 * <p>This drives raw {@link SSLServerSocket}/{@link SSLSocket} instances
 * directly - the same restriction mechanism ({@link
 * SSLParameters#setNamedGroups(String[])}) {@link
 * BcLoopbackHybridPqcTlsHandshakeExecutor} uses internally - rather than
 * going through that executor, since the executor always applies the same
 * (necessarily overlapping) group list to both sides.
 */
class HybridPqcTlsGroupNegotiationFailureTest {

    private final ExecutorService serverExecutor = Executors.newSingleThreadExecutor();

    @AfterEach
    void shutdownExecutor() {
        serverExecutor.shutdownNow();
    }

    @Test
    void handshake_givenNonOverlappingNamedGroups_thenFailsWithNegotiationError() throws Exception {
        IssuedServerCertificate issuedServerCertificate = new BcSelfSignedEcdsaCertificateIssuer().issue();
        HybridPqcTlsContexts contexts =
                new BcSoftwareHybridPqcTlsCryptoBackend().buildContexts(issuedServerCertificate);

        try (SSLServerSocket serverSocket = (SSLServerSocket) contexts.serverContext()
                .getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            applyRestriction(serverSocket, new String[] {"secp256r1"});
            serverSocket.setSoTimeout((int) Duration.ofSeconds(10).toMillis());

            Future<Throwable> serverOutcome = serverExecutor.submit(acceptAndCaptureFailure(serverSocket));

            try (SSLSocket clientSocket =
                    (SSLSocket) contexts.clientContext().getSocketFactory().createSocket()) {
                applyRestriction(clientSocket, new String[] {"X25519MLKEM768"});
                clientSocket.connect(
                        new InetSocketAddress(InetAddress.getLoopbackAddress(), serverSocket.getLocalPort()), 5000);

                assertThatThrownBy(clientSocket::startHandshake).isInstanceOf(IOException.class);
            }

            await().atMost(Duration.ofSeconds(10)).until(serverOutcome::isDone);
            assertThat(serverOutcome.get()).isNotNull();
        }
    }

    private static void applyRestriction(SSLServerSocket socket, String[] namedGroups) {
        SSLParameters parameters = socket.getSSLParameters();
        parameters.setProtocols(new String[] {"TLSv1.3"});
        parameters.setNamedGroups(namedGroups);
        socket.setSSLParameters(parameters);
    }

    private static void applyRestriction(SSLSocket socket, String[] namedGroups) {
        SSLParameters parameters = socket.getSSLParameters();
        parameters.setProtocols(new String[] {"TLSv1.3"});
        parameters.setNamedGroups(namedGroups);
        socket.setSSLParameters(parameters);
    }

    /**
     * Accepts one connection and attempts the handshake, returning whatever exception it throws
     * (a group-mismatched server handshake fails, not succeeds) rather than propagating it, so the
     * test can assert on both sides without one side's {@link Future} failure masking the other's.
     */
    private static Callable<Throwable> acceptAndCaptureFailure(SSLServerSocket serverSocket) {
        return () -> {
            try (SSLSocket accepted = (SSLSocket) serverSocket.accept()) {
                accepted.startHandshake();
                return null;
            } catch (Exception e) {
                return e;
            }
        };
    }
}
