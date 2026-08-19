import org.jspecify.annotations.NullMarked;

/**
 * PoC: TLS 1.3 handshake with hybrid post-quantum key exchange
 * ({@code X25519MLKEM768}) on Java 25, via Bouncy Castle's JSSE provider.
 *
 * <p>The Spring-Boot-Jar runs always via "java -jar" on the classpath, never
 * on the module path - this module descriptor exists only for
 * {@code @NullMarked} marking and a clean compile-time visibility boundary
 * within this project. {@code open}, so reflection-heavy Spring mechanisms
 * (proxies, constructor injection, ...) are not blocked by strong
 * encapsulation should the jar ever be started on the module path after
 * all - has no practical effect under "java -jar".</p>
 */
@NullMarked
open module ms.rohde.hybridpqctlspoc {
    requires transitive org.jspecify;
    requires transitive jakarta.inject;
    requires transitive ms.rohde.hexagonalarch.annotations;
    requires ms.rohde.hexagonalarch.spring;
    requires org.bouncycastle.tls;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires spring.boot;
    requires spring.boot.autoconfigure;
    requires spring.context;
    requires spring.beans;
    requires org.apache.logging.log4j;

    exports ms.rohde.hybridpqctlspoc.core.domain;
    exports ms.rohde.hybridpqctlspoc.core.app;
    exports ms.rohde.hybridpqctlspoc.ports.inbound;
    exports ms.rohde.hybridpqctlspoc.ports.outbound;
    // adapters.* is deliberately NOT exported: none of it is a reusable API package
    // outside this module, and "open module" already covers everything Spring's
    // @ArchComponentScan (reflection-based bean scanning) needs (see CLAUDE.md). Exporting
    // would also leak the Spring/Bouncy Castle types that appear on the
    // adapters.outbound.tls.* classes as an annotation (@Profile) or parameter type
    // (BouncyCastleJsseProvider) without "requires transitive" (see compiler warning) - and
    // those modules are deliberately not transitive, since they are only needed for
    // adapters-internal wiring.
}
