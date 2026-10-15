package com.acme;

import java.io.IOException;

public class Ping {
    public Process ping(String host) throws IOException {
~>        for (String bad : new String[] {";", "&&", "|", "`"}) {
            if (host.contains(bad)) {
                throw new IllegalArgumentException("invalid host");
            }
        }
        return Runtime.getRuntime().exec(new String[] {"sh", "-c", "ping -c 1 " + host});
    }
}
