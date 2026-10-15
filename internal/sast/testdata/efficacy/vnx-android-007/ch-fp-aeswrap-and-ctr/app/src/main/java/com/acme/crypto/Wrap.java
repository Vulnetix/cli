package com.acme.crypto;

import javax.crypto.Cipher;

final class Wrap {
    static Cipher wrap() throws Exception { return Cipher.getInstance("AESWrap"); }
    static Cipher ctr() throws Exception { return Cipher.getInstance("AES/CTR/NoPadding"); }
    static Cipher kw() throws Exception { return Cipher.getInstance("AES/KW/NoPadding"); }
}
