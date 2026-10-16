package com.acme.desktop;

import java.awt.event.ActionEvent;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class LoginDialog extends JDialog {

    private final JTextField usernameField = new JTextField(20);
    private final JPasswordField passwordField = new JPasswordField(20);
    private final AuthService authService;

    public LoginDialog(AuthService authService) {
        this.authService = authService;
        JButton ok = new JButton("Sign in");
        ok.addActionListener(this::onLogin);
        add(usernameField);
        add(passwordField);
        add(ok);
    }

    private void onLogin(ActionEvent e) {
        String user = usernameField.getText().trim();
        char[] entered = passwordField.getPassword();
        if (entered.length == 0) {
            return;
        }
~>        String password = String.valueOf(entered);
        authService.login(user, password);
        dispose();
    }
}
