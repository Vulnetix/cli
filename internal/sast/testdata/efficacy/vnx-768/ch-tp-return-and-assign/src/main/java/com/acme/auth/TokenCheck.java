package com.acme.auth;

import java.util.List;

public class TokenCheck {
    public boolean valid(Token token) {
~>        return token != null & token.isValid();
    }

    public boolean any(List<String> roles) {
~>        boolean present = roles != null & roles.size() > 0;
        return present;
    }
}
