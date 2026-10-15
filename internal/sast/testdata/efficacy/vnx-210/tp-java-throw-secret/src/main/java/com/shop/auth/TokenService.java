package com.shop.auth;

import javax.servlet.http.HttpServletResponse;

public class TokenService {

    public void verify(String accessToken) {
        if (!store.contains(accessToken)) {
~>            throw new IllegalStateException("Unknown access token: " + accessToken);
        }
    }

    public void login(User user, String password, HttpServletResponse response) throws Exception {
        if (!user.matches(password)) {
~>            response.sendError(401, "Password " + password + " does not match for " + user.getName());
        }
    }

    public void connect(DbConfig config) {
        if (!pool.connect(config)) {
~>            throw new RuntimeException(String.format("Cannot connect with %s", config.getPassword()));
        }
    }
}
