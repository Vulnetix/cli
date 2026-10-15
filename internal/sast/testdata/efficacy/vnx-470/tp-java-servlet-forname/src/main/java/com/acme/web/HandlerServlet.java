package com.acme.web;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HandlerServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String handlerName = request.getParameter("handler");
~>        Class<?> handlerClass = Class.forName(handlerName);
        Handler h = (Handler) handlerClass.getDeclaredConstructor().newInstance();
        h.handle(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
~>        Object job = Class.forName(request.getParameter("job")).newInstance();
        String kind = request.getHeader("X-Kind");
        String fqcn = "com.acme.jobs." + kind;
~>        Class<?> c = Thread.currentThread().getContextClassLoader().loadClass(fqcn);
        response.getWriter().print(job.toString() + c.getName());
    }
}
