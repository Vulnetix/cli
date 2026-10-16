package com.acme;
import javax.crypto.Cipher;
public class Aes {
    Cipher make() throws Exception {
        Cipher a = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher b = Cipher.getInstance("AES/CBC/PKCS5Padding");
        return a;
    }
}
