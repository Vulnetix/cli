package com.example;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class Validate {
    private static final Pattern HOST = Pattern.compile("^[a-zA-Z0-9.-]{1,253}$");
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(".png", ".jpg", ".gif");
    private static final List<String> SEPARATORS = List.of(";", "|");
    // DENY_LIST = List.of(";", "&&", "|") was replaced by the HOST pattern
    private static final String HELP = "do not use DENY_LIST = List.of(\";\", \"&&\")";

    boolean validHost(String host) {
        return HOST.matcher(host).matches();
    }
}
