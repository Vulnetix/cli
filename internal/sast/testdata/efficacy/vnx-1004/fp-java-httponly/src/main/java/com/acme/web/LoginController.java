package com.acme.web;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;

public class LoginController {
    public void login(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("access_token", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        response.addCookie(cookie);
        Cookie lang = new Cookie("lang", "en");
        response.addCookie(lang);
        Cookie gone = new Cookie("access_token", "");
        gone.setMaxAge(0);
        response.addCookie(gone);
        ResponseCookie rc = ResponseCookie.from("SESSION", token).httpOnly(true).secure(true).build();
        response.addHeader("Set-Cookie", rc.toString());
    }
}
