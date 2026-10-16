package com.acme.desktop;

import java.io.Console;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class LoginDialog {
    private final JTextField userField = new JTextField(20);
    private final JPasswordField passwordField = new JPasswordField(20);
    private final AuthClient auth;

    public LoginDialog(AuthClient auth) {
        this.auth = auth;
    }

    void onSubmit() {
        String user = userField.getText();
~>        String password = new String(passwordField.getPassword());
        auth.login(user, password);
    }

    static String readFromConsole() {
        Console console = System.console();
~>        return String.valueOf(console.readPassword("Password for %s: ", "admin"));
    }
}
