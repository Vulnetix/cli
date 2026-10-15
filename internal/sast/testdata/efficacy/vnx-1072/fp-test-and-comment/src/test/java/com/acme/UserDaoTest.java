package com.acme;

import java.sql.Connection;
import java.sql.DriverManager;

class UserDaoTest {
    Connection conn() throws Exception {
        return DriverManager.getConnection("jdbc:h2:mem:test");
    }
}
