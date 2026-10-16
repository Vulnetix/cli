package db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

public final class Db {
    static final HikariDataSource DS;

    static {
~>        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl("jdbc:postgresql://db/app");
~>        DS = new HikariDataSource(cfg);
    }
}
