package com.acme.vault;

public class Vault {
    private char[] masterPassword;

    static class Unlocker {
        private final char[] masterPassword;

        Unlocker(char[] p) {
            this.masterPassword = p;
        }
    }

    boolean check(char[] attempt) {
        return Arrays.equals(attempt, masterPassword);
    }
}
