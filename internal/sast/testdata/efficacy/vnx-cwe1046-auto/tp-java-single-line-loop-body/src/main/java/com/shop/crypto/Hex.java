package com.shop.crypto;

public final class Hex {

    public static String encode(byte[] digest) {
        String hex = "";
~>        for (byte b : digest) hex += String.format("%02x", b);
        return hex;
    }

    public static String token(char[] secret) {
        String out;
        out = "";
        for (int i = 0; i < secret.length; i++)
~>            out += secret[i];
        return out;
    }
}
