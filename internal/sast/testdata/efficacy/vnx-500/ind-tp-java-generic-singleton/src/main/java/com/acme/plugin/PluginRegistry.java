package com.acme.plugin;

import java.util.HashMap;
import java.util.Map;

public class PluginRegistry {
~>    public static PluginRegistry INSTANCE = new PluginRegistry();
~>    public static Map<String, Plugin> plugins = new HashMap<>();

    public static PluginRegistry get() {
        return INSTANCE;
    }

    public void register(String name, Plugin plugin) {
        plugins.put(name, plugin);
    }
}
