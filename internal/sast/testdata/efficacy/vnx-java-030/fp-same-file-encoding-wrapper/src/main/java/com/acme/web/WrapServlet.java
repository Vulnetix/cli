package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.util.HtmlUtils;

public class WrapServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String name = request.getParameter("name");
        String shown = clean(name);
        response.getWriter().println("<p>" + shown + "</p>");
        response.getWriter().println(new Helper().render(request.getHeader("X-Name")));
    }

    private static String clean(String raw) {
        String trimmed = raw == null ? "" : raw.trim();
        return HtmlUtils.htmlEscape(trimmed);
    }

    private static class Helper {
        String render(String value) {
            return "<b>" + org.owasp.encoder.Encode.forHtml(value) + "</b>";
        }
    }
}
