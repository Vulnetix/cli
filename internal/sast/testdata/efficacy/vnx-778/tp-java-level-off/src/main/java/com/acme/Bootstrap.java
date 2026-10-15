package com.acme;

import @@sample:o[r]g[.][a]pa[c]he[.]lo[g]4j[.]Le[v]el@@;
import @@sample:o[r]g[.][a]pa[c]he[.]lo[g]4j[.]Lo[g]ge[r]@@;

public class Bootstrap {
    public static void main(String[] args) {
~>        Logger.getRootLogger().setLevel(Level.OFF);
~>        java.util.logging.LogManager.getLogManager().reset();
~>        @@sample:o[r]g[.][a]pa[c]he[.]lo[g]gi[n]g[.][l]og[4]j[.][c]or[e][.]c[o]nf[i]g[.][C]on[f]ig[u]ra[t]or[.]se[t]Ro[o]tL[e]ve[l]@@(@@sample:o[r]g[.][a]pa[c]he[.]lo[g]gi[n]g[.][l]og[4]j[.][L]ev[e]l[.][O]FF@@);
        Server.start(args);
    }
}
