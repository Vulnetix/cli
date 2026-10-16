package com.acme;

import javax.sql.DataSource;

public class ReportServiceTest {
    private DataSource dataSource;

    void run() throws Exception {
        dataSource.getConnection();
    }
}
