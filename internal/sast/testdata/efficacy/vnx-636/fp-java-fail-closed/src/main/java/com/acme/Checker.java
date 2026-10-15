package com.acme;

public class Checker {
    public boolean hasPermission(User u, String p) {
        try {
            return acl.check(u, p);
        } catch (Exception e) {
            log.error("acl failure", e);
            return false;
        }
    }

    public boolean isNumeric(String s) {
        try {
            Long.parseLong(s);
        } catch (NumberFormatException e) {
            return true;
        }
        return false;
    }
}
