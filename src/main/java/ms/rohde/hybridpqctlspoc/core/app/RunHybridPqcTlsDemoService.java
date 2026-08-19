package ms.rohde.hybridpqctlspoc.core.app;

import jakarta.inject.Inject;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.ApplicationService;
import ms.rohde.hybridpqctlspoc.core.domain.CryptoBackendVariant;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsContexts;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsDemoFailedException;
import ms.rohde.hybridpqctlspoc.core.domain.IssuedServerCertificate;
import ms.rohde.hybridpqctlspoc.core.domain.TlsHandshakeOutcome;
import ms.rohde.hybridpqctlspoc.ports.inbound.RunHybridPqcTlsDemoUseCase;
import ms.rohde.hybridpqctlspoc.ports.outbound.EphemeralServerCertificateIssuer;
import ms.rohde.hybridpqctlspoc.ports.outbound.HybridPqcTlsCryptoBackend;
import ms.rohde.hybridpqctlspoc.ports.outbound.HybridPqcTlsHandshakeExecutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Orchestrates one full run of the hybrid PQC TLS demo: issue an ephemeral
 * server certificate, build a matching pair of hybrid-PQC-capable TLS
 * contexts, and drive a local loopback handshake to completion. Translates
 * any failure from the three outbound ports into a single {@link
 * HybridPqcTlsDemoFailedException} identifying the failed stage.
 *
 * <p>A handshake that completes but negotiates a non-hybrid group on either
 * side is also treated as a failure: the whole point of this demo is to
 * prove the hybrid PQC group was actually negotiated, so a silent classical
 * fallback must never be reported as success.
 */
@ApplicationService
public final class RunHybridPqcTlsDemoService implements RunHybridPqcTlsDemoUseCase {

    private static final Logger LOG = LogManager.getLogger(RunHybridPqcTlsDemoService.class);

    private final EphemeralServerCertificateIssuer certificateIssuer;
    private final HybridPqcTlsCryptoBackend cryptoBackend;
    private final HybridPqcTlsHandshakeExecutor handshakeExecutor;

    @Inject
    public RunHybridPqcTlsDemoService(
            EphemeralServerCertificateIssuer certificateIssuer,
            HybridPqcTlsCryptoBackend cryptoBackend,
            HybridPqcTlsHandshakeExecutor handshakeExecutor) {
        this.certificateIssuer = Objects.requireNonNull(certificateIssuer, "certificateIssuer must not be null");
        this.cryptoBackend = Objects.requireNonNull(cryptoBackend, "cryptoBackend must not be null");
        this.handshakeExecutor = Objects.requireNonNull(handshakeExecutor, "handshakeExecutor must not be null");
    }

    @Override
    public TlsHandshakeOutcome run() {
        LOG.info("Starting hybrid PQC TLS demo handshake");

        IssuedServerCertificate issuedServerCertificate = issueCertificate();
        HybridPqcTlsContexts contexts = buildContexts(issuedServerCertificate);
        CryptoBackendVariant variant = cryptoBackend.variant();
        TlsHandshakeOutcome outcome = executeHandshake(contexts, variant);
        verifyHybridPqcGroupNegotiated(outcome);

        LOG.info(
                "Hybrid PQC TLS demo handshake completed: backendVariant={}, "
                        + "serverView=[protocol={}, cipherSuite={}, group={}], "
                        + "clientView=[protocol={}, cipherSuite={}, group={}]",
                outcome.backendVariant(),
                outcome.serverView().protocolVersion(),
                outcome.serverView().cipherSuite(),
                outcome.serverView().negotiatedGroup(),
                outcome.clientView().protocolVersion(),
                outcome.clientView().cipherSuite(),
                outcome.clientView().negotiatedGroup());

        return outcome;
    }

    private IssuedServerCertificate issueCertificate() {
        try {
            return certificateIssuer.issue();
        } catch (RuntimeException e) {
            LOG.error("Hybrid PQC TLS demo failed during certificate issuance", e);
            throw new HybridPqcTlsDemoFailedException("Certificate issuance failed: " + e.getMessage(), e);
        }
    }

    private HybridPqcTlsContexts buildContexts(IssuedServerCertificate issuedServerCertificate) {
        try {
            return cryptoBackend.buildContexts(issuedServerCertificate);
        } catch (RuntimeException e) {
            LOG.error("Hybrid PQC TLS demo failed during TLS context creation", e);
            throw new HybridPqcTlsDemoFailedException("TLS context creation failed: " + e.getMessage(), e);
        }
    }

    private TlsHandshakeOutcome executeHandshake(HybridPqcTlsContexts contexts, CryptoBackendVariant variant) {
        try {
            return handshakeExecutor.execute(contexts, variant);
        } catch (RuntimeException e) {
            LOG.error("Hybrid PQC TLS demo failed during handshake execution", e);
            throw new HybridPqcTlsDemoFailedException("Handshake execution failed: " + e.getMessage(), e);
        }
    }

    private void verifyHybridPqcGroupNegotiated(TlsHandshakeOutcome outcome) {
        boolean serverHybrid = outcome.serverView().hybridPqcGroup();
        boolean clientHybrid = outcome.clientView().hybridPqcGroup();
        if (serverHybrid && clientHybrid) {
            return;
        }

        String message = "Hybrid PQC group was not negotiated: serverView negotiatedGroup="
                + outcome.serverView().negotiatedGroup() + " (hybridPqcGroup=" + serverHybrid + "), clientView "
                + "negotiatedGroup=" + outcome.clientView().negotiatedGroup() + " (hybridPqcGroup=" + clientHybrid
                + ")";
        LOG.error(message);
        throw new HybridPqcTlsDemoFailedException(message);
    }
}
