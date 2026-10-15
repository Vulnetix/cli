package com.acme.core;

public class Settings {
    protected static Settings current;

    public static Settings get() {
        if (null == current) {
            // only one thread builds the settings
~>            synchronized (Settings.class) {
                if (current == null) {
                    current = new Settings();
                }
            }
        }
        return current;
    }
}
