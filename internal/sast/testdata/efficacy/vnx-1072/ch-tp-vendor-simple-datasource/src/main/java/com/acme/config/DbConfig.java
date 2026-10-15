package com.acme.config;

import javax.sql.DataSource;
import org.postgresql.ds.PGSimpleDataSource;

public class DbConfig {
    public DataSource dataSource(String url) {
~>        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(url);
        return ds;
    }

    public DataSource mysql(String url) {
~>        com.mysql.cj.jdbc.MysqlDataSource ds = new com.mysql.cj.jdbc.MysqlDataSource();
        ds.setUrl(url);
        return ds;
    }
}
