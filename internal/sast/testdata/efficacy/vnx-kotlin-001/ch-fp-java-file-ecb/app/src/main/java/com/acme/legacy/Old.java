package com.acme.legacy;

import javax.crypto.Cipher;

class Old {
    Cipher c() throws Exception { return Cipher.getInstance("DES/ECB/PKCS5Padding"); }
}
