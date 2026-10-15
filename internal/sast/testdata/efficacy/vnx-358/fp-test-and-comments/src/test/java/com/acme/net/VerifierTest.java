package com.acme.net;

import javax.net.ssl.HostnameVerifier;

class VerifierTest {
    // conn.setHostnameVerifier((h, s) -> h.endsWith(".acme.com"));
    HostnameVerifier v = (h, s) -> h.endsWith(".test");
    String doc = "setHostnameVerifier((h, s) -> h.contains(\"x\"))";
}
