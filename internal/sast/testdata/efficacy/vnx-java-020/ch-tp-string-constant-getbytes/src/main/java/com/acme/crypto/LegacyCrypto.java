package com.acme.crypto;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class LegacyCrypto {
    private static final String INIT_VECTOR = "abcdefghijklmnop";

    public byte[] encrypt(SecretKey key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(INIT_VECTOR.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@)));
        return c.doFinal(data);
    }
}
