package ms.rohde.hybridpqctlspoc;

import ms.rohde.hexagonalarch.spring.ArchComponentScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Boot entry point of the hybrid PQC TLS PoC.
 *
 * <p>Starts {@link ms.rohde.hybridpqctlspoc.adapters.inbound.cli.HybridPqcTlsDemoRunner},
 * which runs one complete hybrid post-quantum TLS 1.3 handshake demo at
 * startup and terminates - no long-running server, no HTTP port.</p>
 */
@SpringBootApplication
@Configuration
@ArchComponentScan("ms.rohde.hybridpqctlspoc")
public class HybridPqcTlsPocApplication {

    public static void main(String[] args) {
        SpringApplication.run(HybridPqcTlsPocApplication.class, args);
    }
}
