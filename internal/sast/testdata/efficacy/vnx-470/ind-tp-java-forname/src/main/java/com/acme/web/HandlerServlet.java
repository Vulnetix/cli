package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HandlerServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String handlerName = request.getParameter("handler");
        try {
~>            Class<?> handlerClass = Class.forName(handlerName);
            Handler h = (Handler) handlerClass.getDeclaredConstructor().newInstance();
            h.handle(request, response);
        } catch (ReflectiveOperationException e) {
            response.sendError(400);
        }
    }
}
