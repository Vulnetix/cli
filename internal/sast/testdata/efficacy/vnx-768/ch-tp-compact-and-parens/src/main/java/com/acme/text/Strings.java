package com.acme.text;

public final class Strings {
    public static boolean hasText(String s) {
~>        if(s!=null&s.length()>0) return true;
~>        if ((s != null) & (!s.isBlank())) return true;
        return false;
    }
}
