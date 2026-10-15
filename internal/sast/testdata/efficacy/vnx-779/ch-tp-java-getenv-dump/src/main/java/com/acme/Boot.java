package com.acme;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class Boot {
    private static final Logger log = LoggerFactory.getLogger(Boot.class);

    public static void main(String[] a) {
~>        log.info("environment: {}", System.getenv());
    }
}
