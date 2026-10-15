package com.acme.auth;

import java.security.MessageDigest;
import javax.crypto.spec.PBEKeySpec;
import org.mindrot.jbcrypt.BCrypt;

public class Passwords {
    String hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
~>        byte[] out = md.digest(password.getBytes("UTF-8"));
        return new String(out);
    }

    String bc(String password) {
~>        return BCrypt.hashpw(password, BCrypt.gensalt(6));
    }

    PBEKeySpec spec(char[] password, byte[] salt) {
~>        return new PBEKeySpec(password, salt, 1000, 256);
    }
}
