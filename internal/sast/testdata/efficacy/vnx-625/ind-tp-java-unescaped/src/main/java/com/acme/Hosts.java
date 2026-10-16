package com.acme;

import java.util.regex.Pattern;

public class Hosts {
~>    private static final Pattern ALLOWED = Pattern.compile("^https://[a-z]+.example.com");

    public static boolean ok(String origin) {
        return ALLOWED.matcher(origin).find();
    }
}
