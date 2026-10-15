package com.acme;

import java.security.MessageDigest;
import java.text.NumberFormat;

public final class Formats {
~>    public final static NumberFormat CURRENCY = NumberFormat.getCurrencyInstance();
~>    private static MessageDigest sha;

    static {
        try {
            sha = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static String price(double v) {
        return CURRENCY.format(v);
    }

    public static byte[] digest(byte[] in) {
        return sha.digest(in);
    }
}
