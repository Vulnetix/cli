package com.acme.cli;

import java.io.Console;

public class Login {
    public static void main(String[] args) {
        Console console = System.console();
~>        String password = new String(console.readPassword("Password: "));
~>        String pin = String.valueOf(System.console()
                .readPassword("PIN: "));
        authenticate(password, pin);
    }

    static void authenticate(String p, String pin) {}
}
