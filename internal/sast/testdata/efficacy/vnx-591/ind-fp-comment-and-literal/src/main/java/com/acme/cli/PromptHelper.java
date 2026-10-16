package com.acme.cli;

import java.io.Console;
import java.util.Arrays;

/**
 * Reads secrets from the terminal.
 *
 * Do not write new String(console.readPassword()) here: the String cannot be wiped.
 */
public final class PromptHelper {

    private static final String HINT = "avoid String.valueOf(passwordField.getPassword())";

    // String s = new String(console.readPassword("pw"));  -- kept for reference, not used
    public static boolean confirm(Console console, PasswordCheck check) {
        char[] pw = console.readPassword("Password: ");
        try {
            return check.matches(pw);
        } finally {
            Arrays.fill(pw, ' ');
        }
    }

    public static String hint() {
        return HINT;
    }
}
