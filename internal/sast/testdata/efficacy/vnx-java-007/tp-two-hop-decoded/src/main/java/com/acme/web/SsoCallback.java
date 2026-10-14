package com.acme.web;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SsoCallback {
    public void callback(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String raw = request.getParameter("RelayState");
        String relay = URLDecoder.decode(raw, StandardCharsets.UTF_8);
        audit(relay);
~>        response.sendRedirect(relay);
    }

    private void audit(String s) {
    }
}
