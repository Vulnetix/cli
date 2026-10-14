package com.acme.plugins;

public final class PluginGate {

    public boolean trusted(Object plugin) {
~>        if (plugin.getClass().getName().equals("com.acme.plugins.TrustedPlugin")) {
            return true;
        }
~>        return "AdminPlugin".equals(plugin.getClass().getSimpleName());
    }

    public boolean sameKind(Object a, Object b) {
~>        return a.getClass().getName() == b.getClass().getName();
    }
}
