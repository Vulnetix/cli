package com.acme.plugins;

public class Checks {
    boolean isTrusted(Object plugin) {
        if (plugin instanceof TrustedPlugin) {
            return true;
        }
        if (plugin.getClass() == CorePlugin.class) {
            return true;
        }
        if (getName().equals("core")) {
            return true;
        }
        return TrustedPlugin.class.isAssignableFrom(plugin.getClass());
    }

    String describe(Object o) {
        String n = o.getClass().getName();
        log.debug("loaded {}", o.getClass().getSimpleName());
        return n;
    }
}
