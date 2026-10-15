package com.acme.plugins;

import java.util.Map;

public class SafeLoader {
    private static final Map<String, Class<? extends Plugin>> PLUGINS = Map.of(
        "csv", CsvPlugin.class,
        "json", JsonPlugin.class);

    public Plugin load(String kind) throws Exception {
        Class<? extends Plugin> c = PLUGINS.get(kind);
        if (c == null) {
            throw new IllegalArgumentException(kind);
        }
        return c.getDeclaredConstructor().newInstance();
    }

    public Plugin byName(String kind) throws Exception {
        if (!ALLOWED.contains(kind)) {
            throw new IllegalArgumentException(kind);
        }
        return (Plugin) Class.forName("com.acme.plugins.impl." + kind).getDeclaredConstructor().newInstance();
    }
}
