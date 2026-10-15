package com.acme;

import javax.crypto.Cipher;

public class Legacy2 {
    void run() throws Exception {
~>        Cipher a = Cipher.getInstance("DES/CBC/PKCS5Padding");
~>        Cipher b = Cipher.getInstance("ARCFOUR");
~>        Cipher c = Cipher.getInstance("RC2/CBC/PKCS5Padding");
    }
}
