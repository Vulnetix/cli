package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Handler {
    private HttpServletResponse response;

    public void echoed(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Echo echo = new Echo();
        String value = echo.same(param);
~>        response.getWriter().println("<p>" + value + "</p>");
~>        response.getWriter().println("<p>" + echo.same(param) + "</p>");
    }

    public void stored(HttpServletRequest request) throws Exception {
        Slot slot = new Slot(request.getParameter("value"));
        String value = slot.value();
~>        response.getWriter().println("<p>" + value + "</p>");
    }

    public void storedFromLocal(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Slot slot = new Slot(param);
~>        response.getWriter().println("<p>" + slot.value() + "</p>");
    }

    public void replaced(HttpServletRequest request) throws Exception {
        MutableSlot slot = new MutableSlot("report");
        slot.put(request.getParameter("value"));
        String value = slot.value();
~>        response.getWriter().println("<p>" + value + "</p>");
    }

    public void ambiguousClass(HttpServletRequest request) throws Exception {
        com.acme.web.left.Names names = new com.acme.web.left.Names();
        String param = request.getParameter("value");
        String value = names.pick(param);
~>        response.getWriter().println("<p>" + value + "</p>");
    }

    public void unknownClass(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        String value = Registry.lookup(param);
~>        response.getWriter().println("<p>" + value + "</p>");
    }

    public void chained(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Pad pad = new Pad();
        Echo echo = new Echo();
        String value = pad.keep(echo.same(param));
~>        response.getWriter().println("<p>" + value + "</p>");
    }

    public void secondArgument(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Cleaner cleaner = new Cleaner();
        String value = cleaner.choose("fixed", param);
~>        response.getWriter().println("<p>" + value + "</p>");
    }
}
