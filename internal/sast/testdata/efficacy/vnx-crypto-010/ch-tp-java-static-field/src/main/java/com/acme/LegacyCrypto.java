package com.acme;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public final class LegacyCrypto {
~>    private static final byte[] IV = "1234567890123456".getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);

    public static byte[] encrypt(SecretKey key, byte[] in) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
        return cipher.doFinal(in);
    }
}
