package com.acme;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.*;
import org.w3c.dom.Document;

public class PageXPath {
    public String page(HttpServletRequest request, Document doc) throws XPathExpressionException {
        int n = Integer.parseInt(request.getParameter("n"));
        XPath xp = XPathFactory.newInstance().newXPath();
        return xp.evaluate("//page[" + n + "]/title", doc);
    }
}
