package com.acme.util;

import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;

public class Hashing {
~>    private static MessageDigest sha256;
~>    private static final Mac HMAC = initMac();
    private static final Pattern WORD = Pattern.compile("\\w+");
~>    private static final Matcher WORD_MATCHER = WORD.matcher("");

    static {
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static byte[] digest(byte[] in) {
        return sha256.digest(in);
    }
}
