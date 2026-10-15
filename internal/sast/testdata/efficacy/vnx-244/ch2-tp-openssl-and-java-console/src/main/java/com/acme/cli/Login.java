package com.acme.cli;

import java.io.Console;

public class Login {
    public Session prompt(Console console, AuthClient client) {
        char[] typed = console.readPassword("Password: ");
~>        String password = new String(typed);
        return client.login(console.readLine("User: "), password);
    }
}
