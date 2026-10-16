package com.acme.plugins;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Loader {
    private static final Logger log = LoggerFactory.getLogger(Loader.class);

    boolean accept(Object plugin) {
        log.info("loading plugin {}", plugin.getClass().getName());
        if (plugin instanceof SignedPlugin) {
            return true;
        }
        if (plugin.getClass() == CorePlugin.class) {
            return true;
        }
        // old: if (plugin.getClass().getName().equals("com.acme.CorePlugin"))
        String msg = "never compare getClass().getName().equals(\"X\")";
        return SignedPlugin.class.isAssignableFrom(plugin.getClass());
    }

    String describe(Object o) {
        return o.getClass().getSimpleName() + "@" + Integer.toHexString(o.hashCode());
    }
}
