package com.acme.xml;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class XmlLogin {
    private final Document users;

    public XmlLogin(Document users) {
        this.users = users;
    }

    public String login(HttpServletRequest request) throws XPathExpressionException {
        String user = request.getParameter("user");
        String pass = request.getParameter("pass");
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = "/users/user[name='" + user + "' and password='" + pass + "']/id";
~>        return xpath.evaluate(expr, users);
    }
}
