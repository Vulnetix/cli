package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PluginServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        var pluginName = req.getHeader("X-Plugin");
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        try {
~>            Class<?> plugin = Class.forName(pluginName, true, loader);
            resp.getWriter().write(plugin.getSimpleName());
        } catch (ClassNotFoundException e) {
            resp.sendError(404);
        }
    }
}
