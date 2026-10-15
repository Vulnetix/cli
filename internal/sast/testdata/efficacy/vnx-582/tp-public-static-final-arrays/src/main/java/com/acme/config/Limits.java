package com.acme.config;

import java.util.List;

public final class Limits {
~>    public static final int[] RETRY_DELAYS = {100, 200, 400};
~>    public final static String[] ALLOWED_ROLES = new String[] {"admin", "editor"};
~>    static public final byte[] MAGIC = { 0x50, 0x4b };
    private static final int[] INTERNAL = {1, 2};

    private Limits() {}
}
