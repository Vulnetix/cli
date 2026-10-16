package com.acme.crypto;

import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class TicketCipher {
    private final Random rnd = new Random();
    private final SecretKey key;

    public TicketCipher(SecretKey key) {
        this.key = key;
    }

    public byte[] encrypt(byte[] ticket) throws Exception {
        byte[] iv = new byte[16];
~>        rnd.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(ticket);
    }
}
