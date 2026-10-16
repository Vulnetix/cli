package com.acme;

import javax.servlet.http.HttpServletRequest;

public class CsrfFilter {
    public String issue(HttpServletRequest request) {
~>        String csrfToken = Long.toHexString(System.currentTimeMillis()) + request.getRemoteAddr().hashCode();
        request.getSession().setAttribute("csrf", csrfToken);
        return csrfToken;
    }
}
