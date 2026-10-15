package com.acme.ui;

import javax.swing.JPasswordField;

public class LoginPanel {
    private final JPasswordField passwordField = new JPasswordField(20);

    void submit(String user) {
        char[] entered = passwordField.getPassword();
~>        String pass = new String(entered);
        auth.login(user, pass);
    }

    void prompt(java.io.Console console) {
~>        String secret = String.valueOf(console.readPassword("Password: "));
        vault.open(secret);
    }
}
