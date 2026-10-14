package com.acme.auth;

public class LoginService {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(LoginService.class);

    public boolean login(User user, String pwd) {
~>        LOG.debug("Login for " + user.getName() + " with password " + pwd);
~>        System.out.println("api key = " + user.getApiKey());
        return check(user, pwd);
    }
}
