package com.acme;

import java.security.MessageDigest;

class J5 {
    byte[] h(byte[] b) throws Exception {
        return MessageDigest.getInstance("MD5").digest(b);
    }
}
