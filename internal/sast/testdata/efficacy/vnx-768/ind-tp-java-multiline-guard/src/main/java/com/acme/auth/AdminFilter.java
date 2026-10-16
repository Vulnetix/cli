package com.acme.auth;

import javax.servlet.http.HttpServletRequest;

public class AdminFilter {
    public boolean allow(HttpServletRequest request) {
        User user = (User) request.getSession().getAttribute("user");
~>        if (user != null &
                user.getRoles().contains("ADMIN")) {
            return true;
        }
        String[] parts = request.getParameterValues("scope");
~>        boolean scoped = null != parts & parts[0].equals("admin");
        return scoped;
    }
}
