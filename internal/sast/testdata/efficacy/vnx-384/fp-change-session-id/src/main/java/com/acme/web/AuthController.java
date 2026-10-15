package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class AuthController {
    private AccountService accounts;

    public String login(String login, String password, HttpServletRequest req) {
        if (!accounts.checkPassword(login, password)) {
            return "denied";
        }
        req.changeSessionId();
        req.getSession().setAttribute("loggedIn", Boolean.TRUE);
        return "ok";
    }
}
