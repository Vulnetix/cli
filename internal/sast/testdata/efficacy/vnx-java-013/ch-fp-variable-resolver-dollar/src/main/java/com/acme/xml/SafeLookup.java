package com.acme.xml;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class SafeLookup {
    public String find(Document doc, HttpServletRequest request) throws XPathExpressionException {
        final String user = request.getParameter("user");
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setXPathVariableResolver((QName name) -> "user".equals(name.getLocalPart()) ? user : null);
        return xpath.evaluate("/users/user[name=$user]/id", doc);
    }
}
