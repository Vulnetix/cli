package com.acme.cache;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Registry {
    @Deprecated
~>    public static Map<String, List<String>> ROUTES = new HashMap<>();
~>    static public String endpoint;
~>    public static volatile boolean debugEnabled = false;
~>    public static int counter = 0, limit = 10;

    public static Map<String, List<String>> routes() {
        return ROUTES;
    }
}
