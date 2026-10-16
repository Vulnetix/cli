package com.acme.auth;

public class PasswordStore {
    public void save(String user, String password) {
~>        // TODO: passwords are stored with MD5, move to bcrypt
        db.put(user, Hashes.md5(password));
    }
}
