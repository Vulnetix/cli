package com.acme;
import com.zaxxer.hikari.*;
import org.postgresql.ds.PGSimpleDataSource;
public class VendorPooled {
    HikariDataSource build() {
        PGSimpleDataSource pg = new PGSimpleDataSource();
        pg.setServerName("db");
        HikariConfig cfg = new HikariConfig();
        cfg.setDataSource(pg);
        return new HikariDataSource(cfg);
    }
}
