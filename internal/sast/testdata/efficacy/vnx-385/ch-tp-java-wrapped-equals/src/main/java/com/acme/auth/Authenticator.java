package com.acme.auth;

import org.apache.commons.codec.digest.DigestUtils;

public class Authenticator {
    public boolean check(User stored, String input) {
~>        if (!stored.getPassword().equals(DigestUtils.md5Hex(input))) {
            return false;
        }
        return true;
    }

    public boolean checkWrapped(User stored, String input) {
~>        return stored.getPasswordHash()
                .equals(hash(input));
    }

    public boolean checkReverse(String submittedPassword, Account account) {
~>        return submittedPassword.equalsIgnoreCase(account.getPwd());
    }

    private String hash(String s) {
        return @@sample:D[i]ge[s]tU[t]il[s][.]s[h]a2[5]6H[e]x@@(s);
    }
}
