package com.example.ping;

import java.util.Arrays;
import java.util.List;

public class PingService {
~>    private static final List<String> DENY_LIST = List.of(";", "&&", "|");
~>    private static final List<String> SQL_FILTER = Arrays.asList("--", "union", "select");

    String sanitize(String host) {
        String out = host;
        for (String token : DENY_LIST) {
            if (out.contains(token)) {
                out = out.replace(token, "");
            }
        }
        return out;
    }
}
