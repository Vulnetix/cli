package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class SessionFilter {
    private static final String SESSION_COOKIE = "app_session";
    private static final String THEME_COOKIE = "theme";

    void issue(HttpServletResponse response, String id) {
~>        Cookie session = new Cookie(SESSION_COOKIE, id);
        session.setHttpOnly(true);
        response.addCookie(session);
        Cookie theme = new Cookie(THEME_COOKIE, "dark");
        response.addCookie(theme);
        Cookie gone = new Cookie(SESSION_COOKIE, null);
        response.addCookie(gone);
    }
}
