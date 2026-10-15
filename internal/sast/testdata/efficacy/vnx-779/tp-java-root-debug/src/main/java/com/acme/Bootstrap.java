package com.acme;

import @@sample:o[r]g[.][a]pa[c]he[.]lo[g]4j[.]Le[v]el@@;
import @@sample:o[r]g[.][a]pa[c]he[.]lo[g]4j[.]Lo[g]ge[r]@@;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class Bootstrap {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(Bootstrap.class);

    public static void main(String[] args) {
~>        Logger.getRootLogger().setLevel(Level.ALL);
~>        @@sample:o[r]g[.][a]pa[c]he[.]lo[g]gi[n]g[.][l]og[4]j[.][c]or[e][.]c[o]nf[i]g[.][C]on[f]ig[u]ra[t]or[.]se[t]Ro[o]tL[e]ve[l]@@(@@sample:o[r]g[.][a]pa[c]he[.]lo[g]gi[n]g[.][l]og[4]j[.][L]ev[e]l[.][T]RA[C]E@@);
~>        log.info("Environment: {}", System.getenv());
~>        log.debug("props " + System.getProperties());
    }
}
