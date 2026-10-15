package com.acme.net;

import java.util.Arrays;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

public final class Hardening {
    private static final String[] MODERN = {"TLSv1.3", "TLSv1.2"};

    public static void harden(SSLSocket socket) {
        String[] enabled = socket.getEnabledProtocols();
        socket.setEnabledProtocols(Arrays.stream(enabled).filter(p -> !p.equals("TLSv1") && !p.equals("SSLv3")).toArray(String[]::new));
    }

    public static void modern(SSLSocket socket) throws Exception {
        socket.setEnabledProtocols(MODERN);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        java.security.Security.setProperty("jdk.tls.disabledAlgorithms", "SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA");
        log("rejected protocols: SSLv3, TLSv1, TLSv1.1");
    }

    private static void log(String m) {
        System.out.println(m);
    }
}
