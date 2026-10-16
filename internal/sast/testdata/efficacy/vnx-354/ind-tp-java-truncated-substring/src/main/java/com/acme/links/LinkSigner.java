package com.acme.links;

import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;

public class LinkSigner {
    private final byte[] key;

    public LinkSigner(byte[] key) { this.key = key; }

    public boolean isValid(String path, String tag) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        String hash = HexFormat.of().formatHex(mac.doFinal(path.getBytes(StandardCharsets.UTF_8)));
~>        return hash.substring(0, 10).equals(tag);
    }
}
