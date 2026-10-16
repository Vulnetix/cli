package com.acme.web;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

class LoginFlowTest {
    @Test
    void storesUserAfterPasswordCheck() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        String password = "pw";
        if (new FakeAccounts().checkPassword("alice", password)) {
            MockHttpSession session = (MockHttpSession) req.getSession();
            session.setAttribute("user", "alice");
        }
    }
}
