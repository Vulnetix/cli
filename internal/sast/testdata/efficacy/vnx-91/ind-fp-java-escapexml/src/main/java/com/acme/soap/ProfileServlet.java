package com.acme.soap;

import java.io.IOException;
import java.io.StringReader;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.text.StringEscapeUtils;
import org.xml.sax.InputSource;

public class ProfileServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = StringEscapeUtils.escapeXml10(request.getParameter("name"));
        String xml = "<user><name>" + name + "</name></user>";
        String other = "<user><nick>" + StringEscapeUtils.escapeXml10(request.getParameter("nick")) + "</nick></user>";
        String fixed = "<user><role>member</role></user>";
        try {
            DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new InputSource(new StringReader(xml + other + fixed)));
        } catch (Exception e) {
            response.sendError(400);
        }
    }
}
