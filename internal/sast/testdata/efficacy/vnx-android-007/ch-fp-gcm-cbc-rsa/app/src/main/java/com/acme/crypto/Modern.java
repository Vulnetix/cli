package com.acme.crypto;

import javax.crypto.Cipher;

final class Modern {
    static Cipher gcm() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }
    static Cipher cbc() throws Exception { return Cipher.getInstance("AES/CBC/PKCS5Padding"); }
    static Cipher ctr() throws Exception { return Cipher.getInstance("AES_256/GCM/NoPadding"); }
    static Cipher rsa() throws Exception { return Cipher.getInstance("RSA/ECB/@@sample:O[A]EP[W]it[h]SH[A][-]2[5]6A[n]dM[G]F1[P]ad[d]in[g]@@"); }
}
