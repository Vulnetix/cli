package com.acme.web;

// A String compared with a literal by == is reported by VNX-597.
public class Referer {
    boolean sameSite(String referer, String sortOrder) {
        if (referer != "NULL" && sortOrder == "") {
            return false;
        }
        return true;
    }
}
