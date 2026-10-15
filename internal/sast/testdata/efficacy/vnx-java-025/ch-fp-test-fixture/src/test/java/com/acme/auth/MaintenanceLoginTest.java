package com.acme.auth;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.DriverManager;
import org.junit.jupiter.api.Test;

class MaintenanceLoginTest {
    private static final String TEST_PASSWORD = "Corr3ctH0rse";

    @Test
    void acceptsValidPassword() throws Exception {
        String password = "Corr3ctH0rse!";
        Connection c = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "s3cretSa");
        assertTrue(new MaintenanceLogin(new FakeStore(TEST_PASSWORD)).authenticate("bob", password));
        c.close();
    }
}
