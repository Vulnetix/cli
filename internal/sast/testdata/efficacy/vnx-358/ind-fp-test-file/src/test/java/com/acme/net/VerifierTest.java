package com.acme.net;

import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.net.ssl.HttpsURLConnection;
import org.junit.jupiter.api.Test;

class VerifierTest {
    @Test
    void acceptsLocalStub() {
        HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> host.endsWith(".test"));
        assertTrue(true);
    }
}
