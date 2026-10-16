package com.acme;

import org.apache.commons.dbcp2.BasicDataSource;

public final class LegacyPool {
    private static final BasicDataSource DS = new BasicDataSource();

    static {
        DS.setDriverClassName("org.postgresql.Driver");
        DS.setUrl("jdbc:postgresql://db:5432/orders");
~>        DS.setMaxTotal( 2 );
        DS.setMaxIdle(2);
    }

    private LegacyPool() {}

    public static BasicDataSource get() {
        return DS;
    }
}
