package com.acme;

import javax.crypto.Cipher;

public class Wrap {
    Cipher kw() throws Exception { return Cipher.getInstance("AESWrap"); }
    Cipher kw2() throws Exception { return Cipher.getInstance("AES/KW/NoPadding"); }
    Cipher rsa() throws Exception { return Cipher.getInstance("RSA/ECB/PKCS1Padding"); }
}
