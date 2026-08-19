package ms.rohde.hybridpqctlspoc.adapters.inbound.cli;

import jakarta.inject.Inject;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.DrivingAdapter;
import ms.rohde.hybridpqctlspoc.core.domain.HybridPqcTlsDemoFailedException;
import ms.rohde.hybridpqctlspoc.core.domain.NegotiatedTlsParameters;
import ms.rohde.hybridpqctlspoc.core.domain.TlsHandshakeOutcome;
import ms.rohde.hybridpqctlspoc.ports.inbound.RunHybridPqcTlsDemoUseCase;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.CommandLineRunner;

/**
 * Driving CLI demo adapter: runs the hybrid PQC TLS handshake demo once at
 * application startup, logs the outcome, and terminates the process - no
 * long-running server, no HTTP port.
 */
@DrivingAdapter
public final class HybridPqcTlsDemoRunner implements CommandLineRunner {

    private static final Logger LOG = LogManager.getLogger(HybridPqcTlsDemoRunner.class);

    private final RunHybridPqcTlsDemoUseCase useCase;

    @Inject
    public HybridPqcTlsDemoRunner(RunHybridPqcTlsDemoUseCase useCase) {
        this.useCase = Objects.requireNonNull(useCase, "useCase must not be null");
    }

    @Override
    public void run(String... args) {
        try {
            TlsHandshakeOutcome outcome = useCase.run();
            logOutcome(outcome);
        } catch (HybridPqcTlsDemoFailedException e) {
            LOG.error("Hybrid PQC TLS demo failed", e);
            System.exit(1);
        }
    }

    private void logOutcome(TlsHandshakeOutcome outcome) {
        LOG.info("===== Hybrid PQC TLS 1.3 Demo Result =====");
        LOG.info("Backend variant: {}", outcome.backendVariant());
        logView("Server view", outcome.serverView());
        logView("Client view", outcome.clientView());
        LOG.info("Application data round-trip confirmed: {}", outcome.applicationDataConfirmed());
        LOG.info(
                "Hybrid PQC group ({}) negotiated on both sides: {}, backendVariant={}",
                "X25519MLKEM768",
                isHybridConfirmed(outcome),
                outcome.backendVariant());
    }

    private void logView(String label, NegotiatedTlsParameters parameters) {
        LOG.info(
                "{}: protocol={}, cipherSuite={}, negotiatedGroup={}, hybridPqcGroup={}",
                label,
                parameters.protocolVersion(),
                parameters.cipherSuite(),
                parameters.negotiatedGroup(),
                parameters.hybridPqcGroup());
    }

    private static boolean isHybridConfirmed(TlsHandshakeOutcome outcome) {
        return outcome.serverView().hybridPqcGroup() && outcome.clientView().hybridPqcGroup();
    }
}
