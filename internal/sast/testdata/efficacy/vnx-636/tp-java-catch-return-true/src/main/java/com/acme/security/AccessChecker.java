package com.acme.security;

public class AccessChecker {
    public boolean canAccess(User user, Document doc) {
        try {
            return policy.evaluate(user, doc);
        } catch (PolicyException e) {
~>            return true;
        }
    }

    private boolean isTokenValid(String token) {
        try {
            verifier.verify(token);
            return true;
~>        } catch (Exception e) { return true; }
    }

    public boolean hasRole(User u, String role) {
        try {
            return directory.lookup(u).contains(role);
        } catch (Exception e) {
        }
~>        return true;
    }
}
