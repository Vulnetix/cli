package com.acme.feed;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public class FeedServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            SAXParser parser = spf.newSAXParser();
            FeedHandler handler = new FeedHandler();
~>            parser.parse(req.getInputStream(), handler);
            store(handler.items());
        } catch (Exception e) {
            resp.sendError(400);
        }
    }
}
