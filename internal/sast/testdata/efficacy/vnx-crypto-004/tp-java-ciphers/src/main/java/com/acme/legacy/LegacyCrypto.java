package com.acme.legacy;

import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.PBEKeySpec;
import org.bouncycastle.crypto.engines.RC4Engine;

public class LegacyCrypto {

    private static final String TRANSFORMATION = "DESede/CBC/PKCS5Padding";

    public byte[] encrypt(SecretKey key, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    public SecretKey newKey() throws Exception {
~>        return KeyGenerator.getInstance("DES").generateKey();
    }

    public byte[] triple(SecretKey key, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance(TRANSFORMATION);
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    public byte[] provider(SecretKey key, byte[] data) throws Exception {
~>        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("RC4", "SunJCE");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    public byte[] configured(Properties props, SecretKey key, byte[] data) throws Exception {
        String algorithm = props.getProperty("cryptoAlg1", "DESede/ECB/PKCS5Padding");
~>        Cipher c = Cipher.getInstance(algorithm);
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    public SecretKey fromBytes(byte[] raw) throws Exception {
~>        DESKeySpec spec = new DESKeySpec(raw);
~>        return SecretKeyFactory.getInstance("DES").generateSecret(spec);
    }

    public SecretKey passwordKey(char[] pw) throws Exception {
~>        SecretKeyFactory f = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        return f.generateSecret(new PBEKeySpec(pw));
    }

    public Object engine() {
~>        return new RC4Engine();
    }

    public byte[] blowfish(SecretKey key, byte[] data) throws Exception {
~>        Cipher c = Cipher.getInstance(
                "Blowfish/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }
}
