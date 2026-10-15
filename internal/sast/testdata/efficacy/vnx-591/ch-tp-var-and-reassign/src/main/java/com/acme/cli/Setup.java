package com.acme.cli;

import java.io.Console;

public class Setup {
    private char[] adminPw;

    void ask(Console console) {
        var pin = console.readPassword("PIN: ");
~>        String pinText = new String(pin);
        adminPw = console.readPassword("Admin password: ");
~>        store(String.valueOf(adminPw));
    }
}
