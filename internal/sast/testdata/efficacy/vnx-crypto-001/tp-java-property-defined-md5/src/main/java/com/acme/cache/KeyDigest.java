package com.acme.cache;

import java.security.MessageDigest;
import java.util.Properties;

public class KeyDigest {
    private final Properties settings;

    public KeyDigest(Properties settings) {
        this.settings = settings;
    }

    // the file says MD5, so the SHA-256 default never runs
    public byte[] forKey(String key) throws Exception {
        String algorithm = settings.getProperty("cache.digest", "SHA-256");
~>        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(key.getBytes("UTF-8"));
    }

    public byte[] inline(String key) throws Exception {
~>        MessageDigest md = MessageDigest.getInstance(settings.getProperty("cache.digest", "SHA-256"));
        return md.digest(key.getBytes("UTF-8"));
    }

    // defined as SHA-256 in the file, so the MD5 default never runs
    public byte[] fallback(String key) throws Exception {
        String algorithm = settings.getProperty("cache.fallback", "MD5");
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(key.getBytes("UTF-8"));
    }
}
