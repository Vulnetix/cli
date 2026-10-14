package com.acme.xml;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class SafeLookup {
    String find(HttpServletRequest request, Document doc) throws Exception {
        XPath xp = XPathFactory.newInstance().newXPath();
        String id = request.getParameter("id");
        xp.setXPathVariableResolver(v -> new QName("id").equals(v) ? id : null);
        return xp.evaluate("/Employees/Employee[@emplid=$id]", doc);
    }
}
