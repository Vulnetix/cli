package com.example.vault;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class LegacyCrypto {
~>    private static final byte[] IV_BYTES = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
~>    private byte[] ivB = "abcdefghijklmnop".getBytes();

    byte[] enc(Cipher c, javax.crypto.SecretKey key, byte[] in) throws Exception {
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV_BYTES));
        return c.doFinal(in);
    }

    byte[] enc2(Cipher c, javax.crypto.SecretKey key, byte[] in) throws Exception {
~>        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec("0123456789abcdef".getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@)));
~>        byte[] alt = new byte[] { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6 };
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivB));
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(alt));
        return c.doFinal(in);
    }
}
