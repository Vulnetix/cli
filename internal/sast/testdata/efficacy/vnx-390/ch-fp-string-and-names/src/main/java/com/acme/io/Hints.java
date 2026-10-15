package com.acme.io;

public final class Hints {
    public static final String BAD = "try { x(); } catch (Exception e) {}";

    public void parse(String s) {
        try {
            Integer.parseInt(s);
        } catch (NumberFormatException ignored) {}
        try {
            Long.parseLong(s);
        } catch (NumberFormatException expected) {
        }
    }

    // } catch (Exception e) {}
}
