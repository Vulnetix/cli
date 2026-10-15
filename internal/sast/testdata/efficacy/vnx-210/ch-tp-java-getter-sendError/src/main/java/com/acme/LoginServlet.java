package com.acme;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String user = req.getParameter("user");
        String password = req.getParameter("password");
        if (!check(user, password)) {
~>            resp.sendError(401, "Login failed for " + user + " with password " + password);
            return;
        }
    }

    void connect(Credentials creds) {
        if (creds.getUser() == null) {
~>            throw new IllegalStateException("Cannot connect using " + creds.getPassword());
        }
    }

    boolean check(String u, String p) {
        return false;
    }

    interface Credentials {
        String getUser();
        String getPassword();
    }
}
