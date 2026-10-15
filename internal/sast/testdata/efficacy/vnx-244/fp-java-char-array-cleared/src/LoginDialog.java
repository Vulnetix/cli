package app.ui;

import java.util.Arrays;

public class LoginDialog {
    public void submit() {
        char[] password = passwordField.getPassword();
        try {
            auth.login(userField.getText(), password);
        } finally {
            Arrays.fill(password, '\0');
        }
        String label = new String(header.getText());
        String user = form.getPassword() == null ? "" : "set";
    }
}
