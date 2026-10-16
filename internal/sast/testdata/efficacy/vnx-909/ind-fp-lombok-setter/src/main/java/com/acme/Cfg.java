package com.acme;

import lombok.Setter;
import javax.sql.DataSource;

@Setter
public class Cfg {
    private DataSource dataSource;

    public Object conn() throws Exception {
        return dataSource.getConnection();
    }
}
