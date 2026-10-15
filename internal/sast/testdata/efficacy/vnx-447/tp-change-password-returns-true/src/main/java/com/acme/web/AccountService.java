package com.acme.web;

public class AccountService implements PasswordManager {

    @Override
~>    public boolean changePassword(String user, String oldPassword, String newPassword) {
        return true;
    }

    @Override
~>    public boolean revokeSessionTokens(String user) { return Boolean.TRUE; }
}
