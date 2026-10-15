package com.acme.ui;

import javax.swing.JPasswordField;

public class LoginDialog {
    private final JPasswordField passwordInput = new JPasswordField(20);

    String typed() {
~>        String typed = new String(passwordInput.getPassword()).trim();
        return typed;
    }
}
