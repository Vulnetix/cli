package com.acme;
import org.postgresql.ds.PGSimpleDataSource;
import java.sql.Connection;
public class Pg {
    Connection open() throws Exception {
~>        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setServerName("db");
        return ds.getConnection();
    }
}
