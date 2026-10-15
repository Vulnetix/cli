package com.acme.plugins;

public class PluginLoader {
    private static final String BASE = "com.acme.plugins.impl.";

    public Plugin load(String kind) throws Exception {
~>        Class<?> c = Class.forName(BASE + kind + "Plugin");
        return (Plugin) c.getDeclaredConstructor().newInstance();
    }

    public Plugin loadIn(String pkg, String kind, ClassLoader cl) throws Exception {
~>        Class<?> c = Class.forName(pkg + "." + kind,
                true, cl);
        return (Plugin) c.getDeclaredConstructor().newInstance();
    }
}
