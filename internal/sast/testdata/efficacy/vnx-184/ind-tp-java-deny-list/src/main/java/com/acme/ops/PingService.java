package com.acme.ops;

import java.io.IOException;
import java.util.List;

public class PingService {

~>    private static final List<String> DENY_LIST = List.of(";", "&&", "|");

    public Process ping(String host) throws IOException {
        for (String token : DENY_LIST) {
            if (host.contains(token)) {
                throw new IllegalArgumentException("invalid host");
            }
        }
        return Runtime.getRuntime().exec(new String[] {"sh", "-c", "ping -c 1 " + host});
    }
}
