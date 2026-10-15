package com.acme.db;

public class Drivers {
    private static final String DRIVER = "org.postgresql.Driver";

    static void register() throws ClassNotFoundException {
        Class.forName("org.postgresql.Driver");
        Class.forName(DRIVER);
        Class.forName(Drivers.class.getName());
        Class.forName("com.mysql." + "cj.jdbc.Driver");
        Thread.currentThread().getContextClassLoader().loadClass("org.h2.Driver");
    }
}
