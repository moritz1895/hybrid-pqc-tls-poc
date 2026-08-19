package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc;

import jakarta.inject.Inject;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import ms.rohde.hexagonalarch.annotations.InfrastructureServiceAdapter;
import ms.rohde.hybridpqctlspoc.core.domain.CryptoBackendVariant;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsContexts;
import ms.rohde.hybridpqctlspoc.core.domain.NegotiatedTlsParameters;
import ms.rohde.hybridpqctlspoc.core.domain.TlsHandshakeOutcome;
import ms.rohde.hybridpqctlspoc.ports.outbound.HybridPqcTlsHandshakeExecutor;

/**
 * Performs a genuine local loopback TLS 1.3 handshake: binds an {@link
 * SSLServerSocket} on an ephemeral loopback port, connects an {@link
 * SSLSocket} to it, exchanges a fixed demo message and its echo to prove
 * application data actually flows, and captures the negotiated parameters
 * from both sides.
 *
 * <p>Both the server socket and the client socket are restricted, via
 * standard {@link SSLParameters#setProtocols(String[])} and {@link
 * SSLParameters#setNamedGroups(String[])} (the latter added to the JDK in
 * JDK 20, JDK-8288902, and honoured by BCJSSE - see {@code
 * org.bouncycastle.jsse.provider.SSLParametersUtil}), to TLS 1.3 only and the
 * {@code X25519MLKEM768} hybrid group only. This restriction is applied here
 * rather than on the {@link SSLContext} itself: standard {@code
 * javax.net.ssl.SSLContext} has no public method to persist default
 * parameters post-construction, so every real-world BCJSSE usage (including
 * the oscerd/camel-pqc-tls reference implementation) applies it per socket.
 */
@InfrastructureServiceAdapter
public final class BcLoopbackHybridPqcTlsHandshakeExecutor implements HybridPqcTlsHandshakeExecutor {

    private static final String[] RESTRICTED_PROTOCOLS = {"TLSv1.3"};

    /**
     * In TLS 1.3 the {@code supported_groups} extension serves two purposes: key exchange
     * ({@code X25519MLKEM768} here) and ECDSA signature-curve negotiation for the peer
     * certificate ({@code secp256r1}, matching the P-256 demo certificate from {@link
     * ms.rohde.hybridpqctlspoc.adapters.outbound.pki.bc.BcSelfSignedEcdsaCertificateIssuer}).
     * Restricting this list to the hybrid group alone made the handshake fail with {@code
     * handshake_failure(40)} because the server's P-256 certificate had no usable curve left -
     * confirmed against the oscerd/camel-pqc-tls reference client, which offers both for exactly
     * this reason. The actual key exchange still negotiates {@code X25519MLKEM768}, since BCJSSE
     * always prefers a hybrid PQC group over a purely classical one when both are offered.
     */
    private static final String[] RESTRICTED_NAMED_GROUPS = {"X25519MLKEM768", "secp256r1"};
    private static final String HYBRID_GROUP_NAME = "X25519MLKEM768";
    private static final String DEMO_MESSAGE = "hybrid-pqc-tls-poc demo application data";
    private static final long HANDSHAKE_TIMEOUT_SECONDS = 15;

    @Inject
    public BcLoopbackHybridPqcTlsHandshakeExecutor() {}

    @Override
    public TlsHandshakeOutcome execute(HybridPqcTlsContexts contexts, CryptoBackendVariant variant) {
        try (SSLServerSocket serverSocket = createServerSocket(contexts.serverContext())) {
            return runHandshake(serverSocket, contexts.clientContext(), variant);
        } catch (IOException e) {
            throw new HybridPqcTlsHandshakeIoException("Failed to bind the loopback TLS server socket", e);
        }
    }

    private TlsHandshakeOutcome runHandshake(
            SSLServerSocket serverSocket, SSLContext clientContext, CryptoBackendVariant variant) {
        ExecutorService serverExecutor = Executors.newSingleThreadExecutor(BcLoopbackHybridPqcTlsHandshakeExecutor::newDaemonThread);
        try {
            Future<SideOutcome> serverOutcomeFuture = serverExecutor.submit(() -> acceptAndEcho(serverSocket));
            SideOutcome clientOutcome = connectAndExchange(clientContext, serverSocket.getLocalPort());
            SideOutcome serverOutcome = serverOutcomeFuture.get(HANDSHAKE_TIMEOUT_SECONDS, TimeUnit.SECONDS);

            boolean applicationDataConfirmed =
                    DEMO_MESSAGE.equals(clientOutcome.echoedMessage()) && DEMO_MESSAGE.equals(serverOutcome.echoedMessage());
            return new TlsHandshakeOutcome(
                    serverOutcome.parameters(), clientOutcome.parameters(), variant, applicationDataConfirmed);
        } catch (IOException e) {
            throw new HybridPqcTlsHandshakeIoException("Hybrid PQC TLS client-side handshake failed", e);
        } catch (ExecutionException e) {
            throw new HybridPqcTlsHandshakeIoException("Hybrid PQC TLS handshake failed", e.getCause());
        } catch (TimeoutException e) {
            throw new HybridPqcTlsHandshakeIoException("Hybrid PQC TLS handshake timed out", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HybridPqcTlsHandshakeIoException("Hybrid PQC TLS handshake was interrupted", e);
        } finally {
            serverExecutor.shutdownNow();
        }
    }

    private SSLServerSocket createServerSocket(SSLContext serverContext) throws IOException {
        SSLServerSocket serverSocket =
                (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(0, 1, InetAddress.getLoopbackAddress());
        serverSocket.setSSLParameters(restrictedParameters(serverSocket.getSSLParameters()));
        return serverSocket;
    }

    private SideOutcome acceptAndEcho(SSLServerSocket serverSocket) throws IOException {
        try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
            socket.startHandshake();
            String received = readMessage(socket);
            writeMessage(socket, received);
            NegotiatedTlsParameters parameters = toNegotiatedParameters(socket);
            return new SideOutcome(parameters, received);
        }
    }

    private SideOutcome connectAndExchange(SSLContext clientContext, int port) throws IOException {
        try (SSLSocket socket = (SSLSocket) clientContext.getSocketFactory().createSocket()) {
            socket.setSSLParameters(restrictedParameters(socket.getSSLParameters()));
            socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
            socket.startHandshake();
            writeMessage(socket, DEMO_MESSAGE);
            String echoed = readMessage(socket);
            NegotiatedTlsParameters parameters = toNegotiatedParameters(socket);
            return new SideOutcome(parameters, echoed);
        }
    }

    private static SSLParameters restrictedParameters(SSLParameters current) {
        current.setProtocols(RESTRICTED_PROTOCOLS);
        current.setNamedGroups(RESTRICTED_NAMED_GROUPS);
        return current;
    }

    private static void writeMessage(SSLSocket socket, String message) throws IOException {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF(message);
        out.flush();
    }

    private static String readMessage(SSLSocket socket) throws IOException {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        return in.readUTF();
    }

    private static NegotiatedTlsParameters toNegotiatedParameters(SSLSocket socket) {
        SSLSession session = socket.getSession();
        String negotiatedGroup = NegotiatedGroupReader.read(socket);
        return new NegotiatedTlsParameters(
                session.getProtocol(), session.getCipherSuite(), negotiatedGroup, HYBRID_GROUP_NAME.equals(negotiatedGroup));
    }

    private static Thread newDaemonThread(Runnable runnable) {
        Thread thread = new Thread(runnable, "hybrid-pqc-tls-poc-server");
        thread.setDaemon(true);
        return thread;
    }

    private record SideOutcome(NegotiatedTlsParameters parameters, String echoedMessage) {}
}
