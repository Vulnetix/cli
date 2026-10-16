package com.acme.db;

import java.sql.Connection;
import java.sql.DriverManager;
import org.junit.jupiter.api.Test;

class ReplicaFactoryTest {
    private static final String TEST_PASSWORD = "testPass123!";

    @Test
    void connects() throws Exception {
        Connection c = DriverManager.getConnection("jdbc:h2:mem:t", "sa", "testPass123!");
        c.close();
    }
}
