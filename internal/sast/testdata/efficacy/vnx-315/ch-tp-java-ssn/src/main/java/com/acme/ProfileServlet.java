package com.acme;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class ProfileServlet {
    void remember(HttpServletResponse resp, Patient p) {
~>        Cookie c = new Cookie("ssn", p.getSsn());
        c.setMaxAge(86400);
        resp.addCookie(c);
    }
}
