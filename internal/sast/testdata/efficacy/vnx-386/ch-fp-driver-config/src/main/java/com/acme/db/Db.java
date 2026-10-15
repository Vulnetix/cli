package com.acme.db;

public final class Db {
    private static final String DRIVER = "org.postgresql.Driver";

    static {
        try {
            Class.forName(DRIVER);
            Class.forName("com.mysql.cj.jdbc.Driver");
            Class.forName(@@sample:o[r]g[.][h]2[.][D]ri[v]er[.]cl[a]ss[.]ge[t]Na[m]e@@());
        } catch (ClassNotFoundException e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
