package com.acme.plugin;

import java.util.Set;

public final class Loader {
    private static final Set<String> KNOWN_PLUGINS = Set.of("audit", "metrics");
    private static final String BASE = "com.acme.plugin.";

    public Object load(String name) throws ReflectiveOperationException {
        if (!KNOWN_PLUGINS.contains(name)) {
            throw new IllegalArgumentException("unknown plugin " + name);
        }
        return Class.forName(BASE + name).getDeclaredConstructor().newInstance();
    }

    public Object loadChecked(String name) throws ReflectiveOperationException {
        if (!name.matches("[a-z]{1,20}")) {
            throw new IllegalArgumentException("bad name");
        }
        return Class.forName(BASE + name).getDeclaredConstructor().newInstance();
    }

    public String doc() {
        // Class.forName(BASE + name) is only safe after the allow-list check
        return "Class.forName(BASE + name)";
    }
}
