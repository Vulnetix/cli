package com.acme;

import java.security.MessageDigest;

public class Lower {
    byte[] d(byte[] b) throws Exception {
~>        return MessageDigest.getInstance("md5").digest(b);
    }
}
