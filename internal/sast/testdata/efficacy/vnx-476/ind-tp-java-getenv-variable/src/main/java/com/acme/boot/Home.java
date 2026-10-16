package com.acme.boot;

public final class Home {
    public static String pluginsDir() {
        String home = System.getenv("ACME_HOME");
~>        if (home.endsWith("/")) {
            return home + "plugins";
        }
        return home + "/plugins";
    }
}
