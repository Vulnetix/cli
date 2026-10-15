package com.acme;

import java.util.regex.Pattern;

public final class Ids {
    private static final Pattern ID = Pattern.compile("^[0-9]+");

    static boolean valid(String s) {
~>        return ID.matcher(s).find();
    }
}
