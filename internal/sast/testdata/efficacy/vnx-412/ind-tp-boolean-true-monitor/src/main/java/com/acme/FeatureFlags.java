package com.acme;

import java.util.Properties;

public class FeatureFlags {
    private static Properties flags;

    public static boolean enabled(String name) {
        if (flags == null) {
~>            synchronized (Boolean.TRUE) {
                if (flags == null) {
                    flags = FlagLoader.load();
                }
            }
        }
        return Boolean.parseBoolean(flags.getProperty(name));
    }
}
