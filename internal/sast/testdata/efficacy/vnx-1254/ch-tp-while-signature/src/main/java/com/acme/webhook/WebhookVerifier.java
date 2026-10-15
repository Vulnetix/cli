package com.acme.webhook;

public final class WebhookVerifier {
    static boolean verifySignature(String expected, String received) {
        if (expected.length() != received.length()) return false;
        int i = 0;
        while (i < expected.length()) {
~>            if (expected.charAt(i) != received.charAt(i)) return false;
            i++;
        }
        return true;
    }
}
