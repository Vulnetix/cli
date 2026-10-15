package com.acme.ui;

import java.util.Arrays;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class Form {
    private final JPasswordField pwd = new JPasswordField();
    private final JTextField name = new JTextField();

    void submit() {
        String user = new String(name.getText().toCharArray());
        char[] pw = pwd.getPassword();
        try {
            auth.login(user, pw);
        } finally {
            Arrays.fill(pw, '\0');
        }
        String label = String.valueOf(pw.length);
        status.setText(label);
    }
}
