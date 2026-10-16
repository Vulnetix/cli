package com.acme.cfg;

public class Loader {
    private static final boolean DEBUG = Boolean.getBoolean("acme.debug");

    public Config load(String path) {
        if (DEBUG) {
            System.err.println("loading " + path);
        }
        if (Features.LEGACY_FORMAT) {
            return LegacyParser.parse(path);
        }
        // if (false) { cache.clear(); }
        String note = "if (false) { never }";
        return Parser.parse(path, note);
    }
}
