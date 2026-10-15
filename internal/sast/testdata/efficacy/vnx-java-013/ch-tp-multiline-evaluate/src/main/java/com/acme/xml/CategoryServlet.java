package com.acme.xml;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;
import @@sample:o[r]g[.][w]3c[.]do[m][.]N[o]de[L]is[t]@@;

public class CategoryServlet extends HttpServlet {
    private Document inventory;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String category = req.getParameter("category");
        XPath xpath = XPathFactory.newInstance().newXPath();
        try {
~>            NodeList nodes = (NodeList) xpath.evaluate(
                "//item[@category='" + category + "']",
                inventory, XPathConstants.NODESET);
            resp.getWriter().print(nodes.getLength());
        } catch (XPathExpressionException e) {
            resp.sendError(400);
        }
    }
}
