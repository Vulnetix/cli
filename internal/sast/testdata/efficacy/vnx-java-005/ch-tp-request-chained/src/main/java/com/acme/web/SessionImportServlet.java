package com.acme.web;

import java.io.ObjectInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SessionImportServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        try {
~>            Object state = new ObjectInputStream(request.getInputStream()).readObject();
            request.getSession().setAttribute("state", state);
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
    }
}
