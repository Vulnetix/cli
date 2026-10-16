package com.acme.web;

import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class CsrfInit {
    public void init(HttpServletRequest request) {
        HttpSession session = request.getSession();
        session.setAttribute("nonce", UUID.randomUUID().toString());
        session.setAttribute("startedAt", System.currentTimeMillis());
        session.setAttribute("theme", "light");
        Object role = session.getAttribute("role");
        String requested = request.getParameter("view");
        request.setAttribute("view", requested);
    }
}
