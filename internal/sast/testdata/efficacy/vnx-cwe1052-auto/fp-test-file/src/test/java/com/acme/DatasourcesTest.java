package com.acme;

import java.sql.DriverManager;

class DatasourcesTest {
    void connects() throws Exception {
        DriverManager.getConnection("jdbc:mysql://10.0.4.12:3306/orders_test", "test", "test");
    }
}
