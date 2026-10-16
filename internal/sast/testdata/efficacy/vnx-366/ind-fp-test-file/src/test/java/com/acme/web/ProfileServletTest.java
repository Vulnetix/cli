package com.acme.web;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ProfileServletTest {
    static class FakeServlet extends HttpServlet {
        private String captured;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
            captured = req.getParameter("user");
        }
    }
}
