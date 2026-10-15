package com.acme.hooks;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;

public class WebhookVerifier {
    private final byte[] key;

    public WebhookVerifier(byte[] key) {
        this.key = key;
    }

    public boolean verify(byte[] body, String header) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        String computed = Hex.encodeHexString(mac.doFinal(body));
~>        if (!computed.startsWith(header)) {
            return false;
        }
        return true;
    }
}
