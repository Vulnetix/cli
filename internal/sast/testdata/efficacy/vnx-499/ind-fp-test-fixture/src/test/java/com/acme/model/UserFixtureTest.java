package com.acme.model;

import java.io.Serializable;
import org.junit.jupiter.api.Test;

class UserFixtureTest {
    static class FixtureUser implements Serializable {
        private String password = "changeme";
        private String apiKey = "test-key";
    }

    @Test
    void roundTrips() {
        new FixtureUser();
    }
}
