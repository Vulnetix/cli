package com.acme;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import javax.xml.xpath.*;
import org.w3c.dom.Document;

public class BoundXPath {
    public String find(HttpServletRequest request, Document doc) throws XPathExpressionException {
        final String name = request.getParameter("name");
        XPath xp = XPathFactory.newInstance().newXPath();
        xp.setXPathVariableResolver(new XPathVariableResolver() {
            public Object resolveVariable(QName v) { return "n".equals(v.getLocalPart()) ? name : null; }
        });
        return xp.evaluate("//user[name=$n]/email", doc);
    }
}
