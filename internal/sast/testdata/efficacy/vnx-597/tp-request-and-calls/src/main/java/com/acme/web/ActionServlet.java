package com.acme.web;

import javax.servlet.http.HttpServletRequest;

public class ActionServlet {
    void handle(HttpServletRequest request) {
~>        if (request.getParameter("action") == "delete") {
            delete();
        }
~>        if (request.getHeader("X-Mode").toLowerCase() ==
                "debug") {
            debug();
        }
        String user = request.getParameter("user");
~>        if (user.trim() == "root") {
            deny();
        }
    }

    void delete() {}
    void debug() {}
    void deny() {}
}
