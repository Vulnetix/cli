package com.acme.xml;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class EmployeeLookup {
    String find(HttpServletRequest request, Document doc) throws Exception {
        XPath xp = XPathFactory.newInstance().newXPath();
        String id = request.getParameter("id");
        String expression = "/Employees/Employee[@emplid='" + id + "']";
~>        String result = xp.evaluate(expression, doc);
        return result;
    }
}
