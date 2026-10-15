package com.acme.vault;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TokenSealer {
    private final SecretKeySpec key;

    public TokenSealer(SecretKeySpec key) {
        this.key = key;
    }

    public byte[] seal(String token) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
~>        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, "acme-nonce-1".getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@)));
        return cipher.doFinal(token.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
    }
}
