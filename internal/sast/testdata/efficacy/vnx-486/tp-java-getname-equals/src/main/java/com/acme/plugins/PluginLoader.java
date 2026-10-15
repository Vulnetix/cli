package com.acme.plugins;

public class PluginLoader {
    boolean isTrusted(Object plugin) {
~>        if (plugin.getClass().getName().equals("com.acme.plugins.TrustedPlugin")) {
            return true;
        }
~>        return plugin.getClass().getName() == "com.acme.plugins.CorePlugin";
    }

    boolean sameKind(Object a, Object b) {
~>        return a.getClass().getName().equals(b.getClass().getName());
    }
}
