package ms.rohde.hybridpqctlspoc.adapters.outbound.tls.bc;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import javax.net.ssl.SSLSocket;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsContext;

/**
 * Reads the TLS 1.3 named group actually negotiated by a completed Bouncy
 * Castle JSSE ({@code BCJSSE}) handshake.
 *
 * <p>Neither {@code javax.net.ssl.SSLSession} nor BCJSSE's own extended
 * session/connection interfaces ({@code org.bouncycastle.jsse.BCSSLConnection},
 * {@code org.bouncycastle.jsse.BCExtendedSSLSession}) expose the negotiated
 * named group - confirmed by inspecting the bc-java 1.85 sources of
 * {@code org.bouncycastle.jsse.BCSSLConnection}, {@code BCExtendedSSLSession}
 * and {@code org.bouncycastle.jsse.provider.ProvSSLSessionBase}, none of
 * which carry such an accessor. Bouncy Castle's {@code java.util.logging}
 * output likewise never logs the negotiated group on a successful handshake
 * (only configuration warnings for unusable/unsupported configured groups).
 *
 * <p>The value <em>is</em> available through a genuinely typed, public API -
 * {@link SecurityParameters#getNegotiatedGroup()} on {@link TlsContext} - but
 * that context is only reachable from the JSSE-facing {@link SSLSocket}
 * through two package-private/protected implementation details of BCJSSE:
 * the {@code protocol} field on {@code org.bouncycastle.jsse.provider.ProvSSLSocketDirect}
 * (the superclass of every concrete socket BCJSSE hands out) and the
 * {@code protected abstract TlsContext getContext()} method on the public
 * class {@code org.bouncycastle.tls.TlsProtocol}. This class isolates that
 * one reflective bridge; everything downstream of it
 * ({@link TlsContext}, {@link SecurityParameters}, {@link NamedGroup}) is
 * ordinary public Bouncy Castle API.
 */
final class NegotiatedGroupReader {

    private static final String PROTOCOL_FIELD_NAME = "protocol";
    private static final String GET_CONTEXT_METHOD_NAME = "getContext";

    private NegotiatedGroupReader() {}

    static String read(SSLSocket sslSocket) {
        try {
            Object tlsProtocol = readProtocolField(sslSocket);
            TlsContext tlsContext = invokeGetContext(tlsProtocol);
            SecurityParameters securityParameters = tlsContext.getSecurityParametersConnection();
            int negotiatedGroup = securityParameters.getNegotiatedGroup();
            if (negotiatedGroup < 0) {
                throw new NegotiatedGroupUnavailableException(
                        "SecurityParameters.getNegotiatedGroup() returned no group (pre-TLS-1.3 connection?)");
            }
            return NamedGroup.getName(negotiatedGroup);
        } catch (ReflectiveOperationException e) {
            throw new NegotiatedGroupUnavailableException(
                    "Failed to read the negotiated named group from the BCJSSE socket via reflection", e);
        }
    }

    private static Object readProtocolField(SSLSocket sslSocket) throws ReflectiveOperationException {
        Class<?> type = sslSocket.getClass();
        while (type != null) {
            try {
                Field field = type.getDeclaredField(PROTOCOL_FIELD_NAME);
                field.setAccessible(true);
                Object protocol = field.get(sslSocket);
                if (protocol == null) {
                    throw new NegotiatedGroupUnavailableException(
                            "BCJSSE socket has no active TlsProtocol - was the handshake completed?");
                }
                return protocol;
            } catch (NoSuchFieldException e) {
                type = type.getSuperclass();
            }
        }
        throw new NoSuchFieldException(
                PROTOCOL_FIELD_NAME + " field not found on " + sslSocket.getClass() + " or any superclass");
    }

    private static TlsContext invokeGetContext(Object tlsProtocol) throws ReflectiveOperationException {
        Class<?> declaringClass = tlsProtocol.getClass();
        while (declaringClass != null) {
            try {
                Method method = declaringClass.getDeclaredMethod(GET_CONTEXT_METHOD_NAME);
                method.setAccessible(true);
                return (TlsContext) method.invoke(tlsProtocol);
            } catch (NoSuchMethodException e) {
                declaringClass = declaringClass.getSuperclass();
            } catch (InvocationTargetException e) {
                throw new NegotiatedGroupUnavailableException(
                        "TlsProtocol.getContext() threw an exception", e.getCause());
            }
        }
        throw new NoSuchMethodException(
                GET_CONTEXT_METHOD_NAME + "() not found on " + tlsProtocol.getClass() + " or any superclass");
    }
}
