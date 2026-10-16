package com.acme.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TokenIssuer {
    private byte[] signingKey;
    private String apiKey;

~>    private final class HmacSigner implements Signer {
        @Override
        public byte[] sign(byte[] payload) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
            return mac.doFinal(payload);
        }
    }

    Runnable refresher() {
~>        return new Runnable() {
            public void run() {
                apiKey = KeyService.rotate(apiKey);
            }
        };
    }
}
