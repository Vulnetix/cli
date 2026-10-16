package com.acme.web;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.owasp.encoder.Encode;
import org.springframework.web.util.HtmlUtils;

public class SafeServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        String name = request.getParameter("name");
        out.println("<p>" + Encode.forHtml(name) + "</p>");
        out.println("<a title='" + Encode.forHtmlAttribute(name) + "'>x</a>");
        out.println("<script>var n = '" + Encode.forJavaScript(name) + "';</script>");
        out.println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(name));
        out.println(StringEscapeUtils.escapeHtml4(name));
        out.println(HtmlUtils.htmlEscape(request.getHeader("X-Name")));
        out.println(Jsoup.clean(request.getParameter("bio"), Safelist.basic()));
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String name = request.getParameter("name");
        name = HtmlUtils.htmlEscape(name);
        response.getWriter().write("<p>" + name + "</p>");
        String safe = Encode.forHtmlContent(request.getParameter("note"));
        response.getWriter().write(safe);
    }
}
