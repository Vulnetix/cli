package com.acme.sec;

import javax.crypto.Cipher;

public class Legacy {
    Cipher make(boolean compat) throws Exception {
        final String mode = "Blowfish/CBC/PKCS5Padding";
~>        Cipher c = Cipher.getInstance(
                "DESede/CBC/NoPadding");
~>        Cipher d = Cipher.getInstance(mode);
        return compat ? c : d;
    }
}
