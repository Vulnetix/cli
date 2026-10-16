package com.acme;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.*;
import org.w3c.dom.Document;

public class UserLookup {
    public String find(HttpServletRequest request, Document doc) throws XPathExpressionException {
        XPath xp = XPathFactory.newInstance().newXPath();
        String name = request.getParameter("name");
        String expr = "//user[name='" + name + "']/email";
~>        return xp.evaluate(expr, doc);
    }
}
