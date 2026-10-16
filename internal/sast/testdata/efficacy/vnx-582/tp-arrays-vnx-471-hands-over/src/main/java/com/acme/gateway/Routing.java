package com.acme.gateway;

import java.util.List;

public class Routing {
~>    public static final String[] UPSTREAMS = {
        "edge-1.acme.example",
        "edge-2.acme.example",
    };

~>    @Deprecated public static final int[] LEGACY_PORTS = {8081, 8082};

~>    public final static String BLOCKED_PATHS[] = {"/admin", "/actuator"};

~>    static public final char[] SEPARATORS = new char[] { '/', '?' };

    public static final List<String> REGIONS = List.of("eu", "us");
}
