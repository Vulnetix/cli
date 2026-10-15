package com.acme.ui;

import javax.swing.JButton;
import javax.swing.JPasswordField;

public class LoginDialog {
    private final JPasswordField passwordField = new JPasswordField(20);
    private JPasswordField pinField;

    void onSubmit() {
~>        String typed = new String(passwordField.getPassword());
~>        String pin = pinField.getText();
        send(typed, pin);
    }

    void send(String a, String b) {}
}
