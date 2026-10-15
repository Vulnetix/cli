package com.acme.plugins;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PluginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            String impl = req.getHeader("X-Plugin-Impl");
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
~>            Class<?> type = cl.loadClass(impl);
            Object plugin = type.getDeclaredConstructor().newInstance();
            resp.getWriter().print(plugin.toString());
        } catch (ReflectiveOperationException e) {
            resp.sendError(400);
        }
    }
}
