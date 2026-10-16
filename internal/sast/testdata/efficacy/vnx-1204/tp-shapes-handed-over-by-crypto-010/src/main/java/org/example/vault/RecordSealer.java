package org.example.vault;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class RecordSealer {

~>    private static final byte[] FIXED_IV = "vault-iv-0000001".getBytes(StandardCharsets.US_ASCII);

~>    private final byte[] tableIv = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    public byte[] sealRow(SecretKey key, byte[] row) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(FIXED_IV));
        return cipher.doFinal(row);
    }

    public byte[] sealTable(SecretKey key, byte[] table) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(tableIv));
        return cipher.doFinal(table);
    }

    public byte[] sealBlank(SecretKey key, byte[] blob) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
        return cipher.doFinal(blob);
    }

    public byte[] sealText(SecretKey key, byte[] blob) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
~>        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec("abcdefghijklmnop".getBytes("UTF-8")));
        return cipher.doFinal(blob);
    }

    public byte[] sealGcm(SecretKey key, byte[] blob) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
~>        GCMParameterSpec spec = new GCMParameterSpec(128, "nonce-twelve".getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return cipher.doFinal(blob);
    }
}
