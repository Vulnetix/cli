package com.acme.xml;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class FeedServlet extends HttpServlet {
    private static final String TITLE_PATH = "/rss/channel/title";
    private Document feed;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String format = req.getParameter("format");
        XPath xpath = XPathFactory.newInstance().newXPath();
        try {
            String title = xpath.evaluate(TITLE_PATH, feed);
            String count = xpath.evaluate("count(/rss/channel/item)", feed);
            resp.getWriter().print(format + title + count);
        } catch (XPathExpressionException e) {
            resp.sendError(500);
        }
    }
}
