package com.acme.config;

import java.io.InputStream;
import java.util.Properties;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class Settings {
    private static final Logger LOG = LoggerFactory.getLogger(Settings.class);
    private static final Properties PROPS = new Properties();

    static
    {
        try (InputStream in = Settings.class.getResourceAsStream("/app.properties")) {
            PROPS.load(in);
~>        } catch (java.io.IOException e) {
            // ignore, defaults are fine
            LOG.warn("could not load settings", e);
        }
        try { PROPS.setProperty("mode", System.getProperty("mode")); }
~>        catch (NullPointerException ignored) {}
    }
}
