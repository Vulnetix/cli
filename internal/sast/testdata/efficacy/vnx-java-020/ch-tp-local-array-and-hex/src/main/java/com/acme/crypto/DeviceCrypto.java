package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.binary.Hex;

public class DeviceCrypto {
    public byte[] seal(SecretKey key, byte[] data) throws Exception {
        byte[] iv = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
~>        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return c.doFinal(data);
    }

    public byte[] sealHex(SecretKey key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
~>        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(Hex.decodeHex("@@sample:0[0]01[0]20[3]04[0]50[6]07[0]80[9]0a[0]b0[c]0d[0]e0[f]@@")));
        return c.doFinal(data);
    }
}
