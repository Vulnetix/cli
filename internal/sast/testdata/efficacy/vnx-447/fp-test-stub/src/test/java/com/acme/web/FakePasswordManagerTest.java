package com.acme.web;

class FakePasswordManagerTest {
    static class Fake implements PasswordManager {
        public boolean changePassword(String user, String oldPassword, String newPassword) {
            return true;
        }
    }
}
