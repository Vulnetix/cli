package com.acme.net;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

public class LegacyClient {
    public SSLSocket open(String host) throws Exception {
~>        SSLContext ctx = SSLContext.getInstance("TLSv1");
        ctx.init(null, null, null);
        SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, 443);
~>        s.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.1", "TLSv1"});
~>        s.setEnabledCipherSuites(new String[] {"@@sample:S[S]L[_][R]SA[_]WI[T]H[_][R]C4[_]12[8][_]M[D]5@@"});
        return s;
    }

    public SSLContext ssl3() throws Exception {
~>        return SSLContext.getInstance( "SSLv3" );
    }

    static {
~>        System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
~>        java.security.Security.setProperty("jdk.tls.disabledAlgorithms", "");
    }
}
