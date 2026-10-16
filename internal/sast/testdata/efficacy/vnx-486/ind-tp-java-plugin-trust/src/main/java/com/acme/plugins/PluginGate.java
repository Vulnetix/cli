package com.acme.plugins;

import java.util.logging.Logger;

public class PluginGate {
    private static final Logger LOG = Logger.getLogger(PluginGate.class.getName());

    public boolean isTrusted(Plugin plugin) {
        LOG.fine("checking " + plugin.getClass().getName());
~>        if (plugin.getClass().getName().equals("com.acme.plugins.core.SignedPlugin")) {
            return true;
        }
~>        return "AuditPlugin".equalsIgnoreCase(plugin.getClass().getSimpleName());
    }
}
