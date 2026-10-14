package com.acme.auth;

import org.junit.jupiter.api.Test;

class LoginServiceTest {
    @Test
    void logsIn() {
        String password = "test-pass-1";
        new LoginService().login("alice", password);
    }
}
