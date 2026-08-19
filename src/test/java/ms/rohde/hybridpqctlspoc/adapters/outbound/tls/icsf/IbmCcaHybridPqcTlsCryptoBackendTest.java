package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.icsf;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.Security;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class IbmCcaHybridPqcTlsCryptoBackendTest {

    @Test
    void constructor_givenIbmjceccaProviderNotRegistered_thenThrowsProviderUnavailableException() {
        assumeIbmjcccaProviderAbsent();

        assertThatThrownBy(IbmCcaHybridPqcTlsCryptoBackend::new)
                .isInstanceOf(IbmCcaProviderUnavailableException.class)
                .hasMessageContaining("IBMJCECCA");
    }

    private static void assumeIbmjcccaProviderAbsent() {
        Assumptions.assumeTrue(
                Security.getProvider("IBMJCECCA") == null,
                "This test only applies to environments without a registered IBMJCECCA provider "
                        + "(every environment except real z/OS + ICSF + CEX8P hardware).");
    }
}
