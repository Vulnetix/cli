package com.example.bank;

public class SessionTest {
    // prefs.getBoolean("isLoggedIn", false) must not decide access
    void loggedIn() {
        assertTrue(prefs.getBoolean("isLoggedIn", false));
    }
}
