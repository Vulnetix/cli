package com.acme.tools;

import java.io.Console;
import java.nio.file.Path;

public final class KeystoreUnlock {

    private KeystoreUnlock() {
    }

    public static void main(String[] args) throws Exception {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("an interactive console is required");
        }
        Path store = Path.of(args.length > 0 ? args[0] : "keystore.p12");
~>        String storePass = new String(console.readPassword("Keystore password for %s: ", store));
        KeystoreLoader.load(store, storePass);
        console.printf("Unlocked %s%n", store);
    }
}
