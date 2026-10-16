package com.acme.vault;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class CredentialStore {
    private final SecretKey key;
    private final CredentialRepository repo;

    public CredentialStore(SecretKey key, CredentialRepository repo) {
        this.key = key;
        this.repo = repo;
    }

    public void store(String user, String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
~>        byte[] enc = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
        repo.put(user, enc, cipher.getIV());
    }

    public String encodeForExport(Account account) {
~>        return Base64.getEncoder().encodeToString(account.getPassword().getBytes());
    }
}
