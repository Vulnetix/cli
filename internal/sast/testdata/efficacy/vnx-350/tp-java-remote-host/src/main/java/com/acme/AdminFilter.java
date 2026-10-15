package com.acme;

import javax.servlet.http.HttpServletRequest;

public class AdminFilter {
    boolean trusted(HttpServletRequest request) {
~>        if (request.getRemoteHost().endsWith(".internal.example.com")) {
            return true;
        }
        return false;
    }
}
