package com.acme;

import @@sample:o[r]g[.][a]pa[c]he[.]lo[g]4j[.]Le[v]el@@;
import @@sample:o[r]g[.][a]pa[c]he[.]lo[g]4j[.]Lo[g]ge[r]@@;

public class Logs {
    public static void init() {
        Logger root = Logger.getRootLogger();
~>        root.setLevel(Level.OFF);
    }
}
