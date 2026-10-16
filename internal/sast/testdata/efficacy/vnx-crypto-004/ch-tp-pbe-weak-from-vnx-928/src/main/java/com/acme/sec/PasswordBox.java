package com.acme.sec;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordBox {
    Cipher open(char[] password) throws Exception {
~>        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
~>        Cipher cipher = Cipher.getInstance("@@sample:P[B]EW[i]th[S]HA[1]An[d]DE[S]ed[e]@@");
        cipher.init(Cipher.DECRYPT_MODE, factory.generateSecret(new PBEKeySpec(password)));
        return cipher;
    }
}
