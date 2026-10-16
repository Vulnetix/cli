package com.acme.web;

import java.io.BufferedReader;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RenderServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String handler = req.getHeader("X-Render-Handler");
        if (handler == null) {
            resp.sendError(400);
            return;
        }
        try {
~>            Object r = Class.forName(handler).getDeclaredConstructor().newInstance();
            ((Renderer) r).render(req, resp);
        } catch (ReflectiveOperationException e) {
            throw new IOException(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        BufferedReader reader = req.getReader();
        String className = reader.readLine();
        try {
~>            Class<?> c = getClass().getClassLoader().loadClass(className);
            resp.getWriter().println(c.getSimpleName());
        } catch (ClassNotFoundException e) {
            resp.sendError(404);
        }
    }
}
