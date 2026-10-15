package com.acme.cli;

import java.io.Console;
import java.util.Arrays;

public class Unlock {
    boolean run(Vault vault) {
        char[] pw = System.console().readPassword("Vault password: ");
        try {
            return vault.unlock(pw);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }
}
