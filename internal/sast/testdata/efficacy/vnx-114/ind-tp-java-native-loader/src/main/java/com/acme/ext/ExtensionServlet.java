package com.acme.ext;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ExtensionServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String codec = request.getParameter("codec");
~>        System.loadLibrary("codec-" + codec);

        String jar = request.getParameter("jar");
~>        URLClassLoader loader = new URLClassLoader(new URL[] { new URL(jar) },
                getClass().getClassLoader());
        try {
            Class<?> cls = loader.loadClass("com.acme.ext.Plugin");
            response.getWriter().println(cls.getName());
        } catch (ClassNotFoundException e) {
            response.sendError(404);
        }
    }
}
