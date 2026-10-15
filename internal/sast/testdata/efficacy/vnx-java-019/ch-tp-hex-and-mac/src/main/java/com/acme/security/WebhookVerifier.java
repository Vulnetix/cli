package com.acme.security;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;

public class WebhookVerifier {
    public byte[] sign(byte[] body) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
~>        mac.init(new SecretKeySpec("@@sample:w[h]se[c][-]a[c]me[-]sh[a]re[d][-]w[e]bh[o]ok@@".getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@), "HmacSHA256"));
        return mac.doFinal(body);
    }

    public Cipher cipher() throws Exception {
        byte[] key = Hex.decodeHex("@@sample:0[0]11[2]23[3]44[5]56[6]77[8]89[9]aa[b]bc[c]dd[e]ef[f]@@".toCharArray());
~>        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        return c;
    }
}
