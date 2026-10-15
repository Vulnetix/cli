package com.acme;

public class Clean {
    public static String path(String p) {
~>        return p.replaceAll("\\.\\./", "");
    }
}
