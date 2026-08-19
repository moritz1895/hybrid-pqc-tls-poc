package ms.rohde.hybridpqctlspoc;

import static org.assertj.core.api.Assertions.assertThat;

import ms.rohde.hexagonalarch.spring.ArchComponentScan;
import ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc.BcSoftwareHybridPqcTlsCryptoBackend;
import ms.rohde.hybridpqctlspoc.adapters.outbound.tls.icsf.IbmCcaProviderUnavailableException;
import ms.rohde.hybridpqctlspoc.core.domain.CryptoBackendVariant;
import ms.rohde.hybridpqctlspoc.ports.outbound.HybridPqcTlsCryptoBackend;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

/**
 * Proves that Spring's {@code @Profile} wiring genuinely selects the crypto
 * backend variant - not just that {@link BcSoftwareHybridPqcTlsCryptoBackend}
 * and {@code IbmCcaHybridPqcTlsCryptoBackend} each work correctly in
 * isolation (already covered elsewhere), but that a real Spring container
 * driven by this project's {@link ArchComponentScan} setup resolves exactly
 * one {@link HybridPqcTlsCryptoBackend} bean per profile, with no silent
 * ambiguity and no silent fallback.
 *
 * <p>Scoped to a minimal {@link ScanConfiguration} - the same {@code
 * @ArchComponentScan("ms.rohde.hybridpqctlspoc")} declaration {@link
 * HybridPqcTlsPocApplication} carries - rather than booting the full {@code
 * @SpringBootApplication}, so this stays a lightweight context test.
 */
class HybridPqcTlsCryptoBackendSpringWiringTest {

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner().withUserConfiguration(ScanConfiguration.class);

    @Test
    void context_givenNoActiveProfile_thenResolvesSoftwareBackend() {
        contextRunner.run(context -> {
            assertThat(context).hasNotFailed();

            HybridPqcTlsCryptoBackend backend = context.getBean(HybridPqcTlsCryptoBackend.class);
            assertThat(backend).isInstanceOf(BcSoftwareHybridPqcTlsCryptoBackend.class);
            assertThat(backend.variant()).isEqualTo(CryptoBackendVariant.SOFTWARE);
        });
    }

    @Test
    void context_givenIbmCcaProfileActive_thenStartupFailsFastInsteadOfFallingBackOrStartingAmbiguously() {
        contextRunner.withPropertyValues("spring.profiles.active=ibm-cca").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasRootCauseInstanceOf(IbmCcaProviderUnavailableException.class);
        });
    }

    @Configuration
    @ArchComponentScan("ms.rohde.hybridpqctlspoc")
    static class ScanConfiguration {}
}
