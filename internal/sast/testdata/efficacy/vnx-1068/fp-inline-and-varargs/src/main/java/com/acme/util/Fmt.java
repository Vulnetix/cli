package com.acme.util;

public interface Fmt {
    /**
     * @param pattern the pattern
     * @param args the arguments
     */
    String format(String pattern, Object... args);

    /**
     * Stores the value.
     *
     * @param value the value
     */
    // TODO: tighten
    void store(Object value);

    String HELP = "@param nope";
}
