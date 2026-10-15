package com.acme.auth;

import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyLoader {
    private final VaultClient vault;

    public KeyLoader(VaultClient vault) {
        this.vault = vault;
    }

    public SecretKeySpec load(String name) {
        byte[] raw = Base64.getDecoder().decode(vault.read(name));
        return new SecretKeySpec(raw, "AES");
    }

    public SecretKey fresh() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("HmacSHA256");
        return gen.generateKey();
    }
}
