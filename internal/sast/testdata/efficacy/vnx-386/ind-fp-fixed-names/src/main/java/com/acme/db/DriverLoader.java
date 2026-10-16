package com.acme.db;

public final class DriverLoader {
    private static final String DRIVER_CLASS = "org.postgresql.Driver";

    public static void load() throws ClassNotFoundException {
        Class.forName("org.postgresql.Driver");
        Class.forName(DRIVER_CLASS);
        Class.forName("org.h2." + "Driver");
        Class.forName(DriverLoader.class.getName());
        Thread.currentThread().getContextClassLoader().loadClass(org.h2.Driver.class.getName());
    }
}
