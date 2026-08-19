package ms.rohde.hybridpqctlspoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CryptoBackendVariantTest {

    @Test
    void values_givenEnum_thenContainsExactlySoftwareAndIbmCcaHardware() {
        assertThat(CryptoBackendVariant.values())
                .containsExactly(CryptoBackendVariant.SOFTWARE, CryptoBackendVariant.IBM_CCA_HARDWARE);
    }

    @Test
    void valueOf_givenSoftware_thenReturnsSoftwareConstant() {
        assertThat(CryptoBackendVariant.valueOf("SOFTWARE")).isEqualTo(CryptoBackendVariant.SOFTWARE);
    }

    @Test
    void valueOf_givenIbmCcaHardware_thenReturnsIbmCcaHardwareConstant() {
        assertThat(CryptoBackendVariant.valueOf("IBM_CCA_HARDWARE")).isEqualTo(CryptoBackendVariant.IBM_CCA_HARDWARE);
    }
}
