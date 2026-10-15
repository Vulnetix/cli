package com.acme.vault;

public class Vault {
    private char[] masterPassword;
    private String label;

~>    class Unlocker {
        boolean unlock(char[] attempt) {
            return Arrays.equals(attempt, masterPassword);
        }
    }
}
