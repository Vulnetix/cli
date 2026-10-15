package com.acme;

import java.util.Arrays;
import javax.net.ssl.SSLSocket;

public class Tls {
    void harden(SSLSocket s) {
        String[] enabled = Arrays.stream(s.getEnabledCipherSuites())
            .filter(c -> !c.contains("RC4") && !c.contains("DES"))
            .toArray(String[]::new);
        s.setEnabledCipherSuites(enabled);
    }
}
