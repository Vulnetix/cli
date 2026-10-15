package com.acme.vault;

import java.util.Map;
import java.util.HashMap;

public final class Defaults {
~>    public static final char[] MASTER_PASSWORD = {'c', 'h', 'a', 'n', 'g', 'e'};
~>    public static final byte[] ENCRYPTION_KEY = new byte[16];
~>    public static Map<String, String> credentials = new HashMap<>();

    private Defaults() {}
}
