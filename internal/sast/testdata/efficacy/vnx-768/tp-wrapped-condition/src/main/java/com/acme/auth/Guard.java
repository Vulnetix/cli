package com.acme.auth;

public class Guard {
    boolean allowed(Session session) {
~>        return session != null &
            session.isAuthenticated();
    }
}
