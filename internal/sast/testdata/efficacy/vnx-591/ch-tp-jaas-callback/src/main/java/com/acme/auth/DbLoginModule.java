package com.acme.auth;

import javax.security.auth.callback.PasswordCallback;

public class DbLoginModule {
    private String password;

    void handle(PasswordCallback pc) {
~>        password = new String(pc.getPassword());
        pc.clearPassword();
    }
}
