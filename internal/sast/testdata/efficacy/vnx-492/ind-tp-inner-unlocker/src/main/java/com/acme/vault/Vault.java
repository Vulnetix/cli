package com.acme.vault;

import java.util.Arrays;

public class Vault {
    private char[] masterPassword;
    private int attempts;

~>    class Unlocker {
        boolean tryUnlock(char[] attempt) {
            attempts++;
            return Arrays.equals(attempt, masterPassword);
        }
    }

    public Unlocker unlocker() {
        return new Unlocker();
    }
}
