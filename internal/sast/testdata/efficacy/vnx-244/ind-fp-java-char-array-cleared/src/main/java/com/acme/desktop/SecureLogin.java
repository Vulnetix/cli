package com.acme.desktop;

import java.util.Arrays;
import javax.swing.JPasswordField;

public class SecureLogin {
    private final JPasswordField passwordField = new JPasswordField(20);
    private final AuthClient auth;

    public SecureLogin(AuthClient auth) {
        this.auth = auth;
    }

    void onSubmit(String user) {
        char[] password = passwordField.getPassword();
        try {
            auth.login(user, password);
        } finally {
            Arrays.fill(password, '\0');
        }
        String label = new String(userLabelChars());
        System.out.println(label);
    }

    private char[] userLabelChars() {
        return "user".toCharArray();
    }
}
