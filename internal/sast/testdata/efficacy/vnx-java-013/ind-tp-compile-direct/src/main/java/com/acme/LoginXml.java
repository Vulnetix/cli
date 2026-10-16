package com.acme;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.*;

public class LoginXml {
    public XPathExpression build(HttpServletRequest req) throws XPathExpressionException {
        XPath xpath = XPathFactory.newInstance().newXPath();
~>        return xpath.compile("/users/user[@id='" + req.getParameter("id") + "' and @pw='x']");
    }
}
