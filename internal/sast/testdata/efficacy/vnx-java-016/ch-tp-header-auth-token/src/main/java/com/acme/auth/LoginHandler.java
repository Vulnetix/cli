package com.acme.auth;

import java.util.Random;
import javax.servlet.http.HttpServletResponse;

public class LoginHandler {
    public void onSuccess(HttpServletResponse response) {
~>        response.setHeader("X-Auth-Token", String.valueOf(new Random().nextLong()));
    }
}
