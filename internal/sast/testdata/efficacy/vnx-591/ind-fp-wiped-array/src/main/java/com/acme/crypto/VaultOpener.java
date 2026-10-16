package com.acme.crypto;

import java.io.Console;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class VaultOpener {

    public byte[] deriveKey(byte[] salt) throws Exception {
        Console console = System.console();
        char[] pw = console.readPassword("Vault passphrase: ");
        PBEKeySpec spec = new PBEKeySpec(pw, salt, 310_000, 256);
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return f.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
            Arrays.fill(pw, '\0');
        }
    }
}
