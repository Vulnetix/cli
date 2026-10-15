package com.example.web;

import javax.servlet.http.HttpServletRequest;

public class CsrfGuard {

~>    public boolean validateCsrfToken(HttpServletRequest request) {
        // TODO compare with the session token before release
        return true;
    }
}
