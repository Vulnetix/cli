package com.acme.db;

import java.lang.reflect.Method;

public final class Db {
    private static final String DRIVER = "org.postgresql.Driver";

    static void init(Config config) throws Exception {
        Class.forName(DRIVER);
        Class<?> c = Class.forName("com.acme.db.Migrator");
        Method m = c.getMethod("run", Config.class);
        String impl = config.get("db.dialect");
        Class.forName(impl);
    }
}
