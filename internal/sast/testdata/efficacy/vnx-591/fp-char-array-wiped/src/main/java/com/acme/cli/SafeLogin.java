package com.acme.cli;

import java.io.Console;
import java.util.Arrays;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class SafeLogin {
    private JPasswordField passwordField;
    private JTextField userField;

    void run(Console console) {
        char[] pw = console.readPassword("Password: ");
        try {
            verify(pw);
        } finally {
            Arrays.fill(pw, '\0');
        }
        char[] fromField = passwordField.getPassword();
        verify(fromField);
        String user = userField.getText();
        char[] letters = {'a', 'b'};
        String word = new String(letters);
    }

    void verify(char[] p) {}
}
