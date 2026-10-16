package com.acme;
import com.zaxxer.hikari.*;
import java.sql.Connection;
import javax.naming.InitialContext;
import javax.sql.DataSource;
public class Pool {
    HikariDataSource ds;
    Pool() {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl("jdbc:postgresql://db/app");
        ds = new HikariDataSource(cfg);
    }
    Connection get() throws Exception { return ds.getConnection(); }
    Connection jndi() throws Exception {
        DataSource d = (DataSource) new InitialContext().lookup("java:comp/env/jdbc/app");
        return d.getConnection();
    }
}
