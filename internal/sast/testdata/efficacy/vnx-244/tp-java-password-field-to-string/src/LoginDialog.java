package app.ui;

import javax.swing.JPasswordField;

public class LoginDialog {
    private JPasswordField passwordField;

    public void submit() {
~>        String password = new String(passwordField.getPassword());
        auth.login(userField.getText(), password);
    }

    public void unlock(java.io.Console console) {
~>        String pin = String.valueOf(console.readPassword("PIN: "));
        vault.open(pin);
    }
}
