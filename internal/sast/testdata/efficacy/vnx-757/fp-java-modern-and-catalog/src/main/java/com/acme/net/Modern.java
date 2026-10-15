package com.acme.net;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

public class Modern {
    // Older JDKs used SSLContext.getInstance("TLSv1"); never again.
    private static final String LEGACY_NOTE = "TLSv1 and TLSv1.1 are disabled";

    enum Version {
        TLS_1_1("TLSv1.1"),
        TLS_1_0("TLSv1"),
        SSL_3_0("SSLv3");

        final String javaName;
        Version(String n) { this.javaName = n; }
    }

    static Version parse(String name) {
        switch (name) {
            case "TLSv1": return Version.TLS_1_0;
            case "SSLv3": return Version.SSL_3_0;
            default: return null;
        }
    }

    public SSLSocket open(SSLContext unused) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        SSLContext any = SSLContext.getInstance("TLS");
        ctx.init(null, null, null);
        SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket("example.org", 443);
        s.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
        s.setEnabledCipherSuites(new String[] {"@@sample:T[L]S[_][A]ES[_]12[8][_]G[C]M[_][S]HA[2]56@@"});
        java.security.Security.setProperty("jdk.tls.disabledAlgorithms", "SSLv3, TLSv1, TLSv1.1, RC4, DES");
        return s;
    }
}
