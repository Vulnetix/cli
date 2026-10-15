package com.acme.web;

public class Notes {
    // if (uri.startsWith("/admin")) deny; then URLDecoder.decode(uri) -- wrong order
    private static final String HINT = "if (uri.startsWith(\"/admin\")) { } URLDecoder.decode(uri)";

    public String hint() {
        return HINT;
    }
}
