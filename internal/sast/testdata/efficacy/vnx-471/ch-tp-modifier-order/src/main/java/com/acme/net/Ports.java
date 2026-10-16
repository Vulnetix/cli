package com.acme.net;

import java.util.HashMap;
import java.util.Map;

public class Ports {
    public final static int[] DEFAULT_PORTS = {80, 443, 8080};
~>    static public final Map<String, Integer> SERVICE_PORTS = new HashMap<>();

    static {
        SERVICE_PORTS.put("http", 80);
    }
}
