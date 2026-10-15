package com.acme;

import @@sample:o[r]g[.][a]pa[c]he[.]lo[g]4j[.]Le[v]el@@;
import @@sample:o[r]g[.][a]pa[c]he[.]lo[g]4j[.]Lo[g]ge[r]@@;

public class Bootstrap {
    public static void main(String[] args) {
        Logger.getRootLogger().setLevel(Level.INFO);
        Logger.getLogger("org.hibernate").setLevel(Level.WARN);
        // Logger.getRootLogger().setLevel(Level.OFF);
        String help = "setLevel(Level.OFF) silences everything";
    }
}
