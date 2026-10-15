package com.acme.sec;

import java.security.Security;
import javax.net.ssl.SSLContext;

public class TlsHardening {
    static final String[] BANNED = {"DES", "RC4", "DESede", "Blowfish"};

    static void harden() throws Exception {
        Security.setProperty("jdk.tls.disabledAlgorithms", "SSLv3, RC4, DES, 3DES_EDE_CBC");
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        if (java.util.Arrays.asList(BANNED).contains("RC4")) {
            System.out.println("RC4 banned");
        }
    }
}
