package com.acme.tls;

import java.util.Set;

public final class Suites {
    // Suites rejected during the handshake audit.
    static final Set<String> BLOCKED = Set.of(
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
    );

    static boolean blocked(String suite) {
        return BLOCKED.contains(suite) || suite.contains("_DES_") || suite.contains("RC4");
    }
}
