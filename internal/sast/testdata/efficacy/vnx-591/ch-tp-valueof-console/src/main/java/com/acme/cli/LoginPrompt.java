package com.acme.cli;

import java.io.Console;

public class LoginPrompt {
    public String ask() {
        Console console = System.console();
~>        String secret = String.valueOf(console.readPassword("Password: "));
        return secret;
    }
}
