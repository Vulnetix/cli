package com.example;

import org.mindrot.jbcrypt.BCrypt;

public class Passwords {
    public boolean matches(String raw, String hash) {
        return BCrypt.checkpw(raw, hash);
    }

    public void require(String raw, String hash) {
        if (!BCrypt.checkpw(raw, hash)) {
            throw new SecurityException("bad password");
        }
    }
}
