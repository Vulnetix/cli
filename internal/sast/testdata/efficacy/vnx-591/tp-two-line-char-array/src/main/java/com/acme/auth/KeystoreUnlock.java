package com.acme.auth;

import java.io.Console;
import java.security.KeyStore;
import javax.security.auth.callback.PasswordCallback;

public class KeystoreUnlock {
    String unlock(Console console) {
        char[] secret = console.readPassword("Keystore password: ");
        int attempts = 0;
~>        String asText = new String(secret);
        return asText;
    }

    String fromCallback(PasswordCallback pc) {
        final char[] pw = pc.getPassword();
~>        return String.copyValueOf(pw);
    }

    String fromProtection(KeyStore.PasswordProtection prot) {
~>        return String.valueOf(prot.getPassword());
    }
}
