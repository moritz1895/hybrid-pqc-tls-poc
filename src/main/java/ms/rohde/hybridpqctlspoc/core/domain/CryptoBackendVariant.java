package ms.rohde.hybridpqctlspoc.core.domain;

import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * Identifies which of the two crypto backend variants performed the ML-KEM
 * part of the hybrid key exchange for a given demo run.
 */
@DomainValueObject
public enum CryptoBackendVariant {

    /**
     * Both the classical X25519 and the ML-KEM part of the key exchange run
     * entirely in software, via Bouncy Castle.
     */
    SOFTWARE,

    /**
     * The ML-KEM part of the key exchange is routed to the {@code
     * IBMJCECCA} JCE provider, backed by IBM's ICSF/CCA cryptographic
     * hardware, while the classical X25519 part still runs in software.
     */
    IBM_CCA_HARDWARE
}
