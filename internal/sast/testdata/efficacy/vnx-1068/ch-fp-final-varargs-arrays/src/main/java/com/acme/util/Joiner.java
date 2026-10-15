package com.acme.util;

public final class Joiner {
    /**
     * Joins parts.
     *
     * @param sep   the separator
     * @param parts the parts
     * @param out   destination buffer
     * @param lens  lengths
     */
    public static void join(final String sep,
                            @Nullable StringBuilder out,
                            int lens[],
                            final Object... parts) {
    }

    /**
     * Logs.
     *
     * @param message the message
     */
    // keep the old name for callers
    @Deprecated
    void log(String message) {
    }
}
