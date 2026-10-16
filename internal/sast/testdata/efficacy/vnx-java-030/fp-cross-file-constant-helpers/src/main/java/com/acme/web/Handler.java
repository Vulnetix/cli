package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Handler {
    private HttpServletResponse response;

    public void sanitized(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Cleaner cleaner = new Cleaner();
        String value = cleaner.clean(param);
        response.getWriter().println("<p>" + value + "</p>");
    }

    public void sanitizedInline(HttpServletRequest request) throws Exception {
        Cleaner cleaner = new Cleaner();
        String value = cleaner.clean(request.getParameter("value"));
        response.getWriter().println("<p>" + value + "</p>");
    }

    public void settings() throws Exception {
        Settings settings = new Settings();
        String value = settings.name();
        response.getWriter().println("<p>" + value + "</p>");
        response.getWriter().println("<p>" + Settings.fixed() + "</p>");
        response.getWriter().println("<p>" + settings.ext() + "</p>");
    }

    public void storedLiteral() throws Exception {
        Slot slot = new Slot("report");
        String value = slot.value();
        response.getWriter().println("<p>" + value + "</p>");
    }

    public void chained(HttpServletRequest request) throws Exception {
        Settings settings = new Settings();
        Pad pad = new Pad();
        String value = pad.keep(pad.keep(settings.name()));
        response.getWriter().println("<p>" + value + "</p>");
        String second = new Cleaner().choose(request.getParameter("value"), "fixed");
        response.getWriter().println("<p>" + second + "</p>");
    }
}
