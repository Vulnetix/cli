package com.acme;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;

public class Legacy {
    void run() throws Exception {
~>        KeyGenerator kg = KeyGenerator.getInstance("DESede");
~>        SecretKeyFactory f = SecretKeyFactory.getInstance("DES");
~>        Cipher c = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
~>        Cipher r = Cipher.getInstance("RC4");
    }
}
