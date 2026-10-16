package ui;

import javax.swing.*;

public class LoginDialog extends JDialog {
    private final JPasswordField passwordField = new JPasswordField(20);

    void onOk() {
        char[] raw = passwordField.getPassword();
~>        String pw = String.valueOf(raw);
        service.login(pw);
    }
}
