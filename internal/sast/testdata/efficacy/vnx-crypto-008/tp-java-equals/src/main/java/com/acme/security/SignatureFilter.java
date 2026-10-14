package com.acme.security;

import java.util.Arrays;
import javax.crypto.Mac;
import javax.servlet.http.HttpServletRequest;

public class SignatureFilter {

    boolean verify(HttpServletRequest request, Mac mac, byte[] body) {
        String computed = hex(mac.doFinal(body));
        String signature = request.getHeader("X-Signature");
~>        return computed.equals(signature);
    }

    boolean verifyBytes(byte[] expectedMac, byte[] providedMac) {
~>        return Arrays.equals(expectedMac, providedMac);
    }

    boolean apiToken(HttpServletRequest request, String token) {
~>        return token.equals(request.getHeader("X-Api-Token"));
    }

    private String hex(byte[] b) { return ""; }
}
