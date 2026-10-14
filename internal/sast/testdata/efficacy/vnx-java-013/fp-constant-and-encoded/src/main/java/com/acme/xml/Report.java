package com.acme.xml;

import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.owasp.esapi.ESAPI;
import org.w3c.dom.Document;

public class Report {
    private static final String ALL = "/Employees/Employee/Salary";

    String run(HttpServletRequest request, Document doc) throws Exception {
        XPath xp = XPathFactory.newInstance().newXPath();
        String total = xp.evaluate(ALL, doc);
        String filter = request.getParameter("filter");
        Pattern p = Pattern.compile(filter);
        String dept = ESAPI.encoder().encodeForXPath(request.getParameter("dept"));
        String byDept = xp.evaluate("/Employees/Employee[@dept='" + dept + "']", doc);
        int n = Integer.parseInt(request.getParameter("n"));
        return xp.evaluate("/Employees/Employee[" + n + "]/Name", doc) + total + byDept;
    }

    private String countOf(String element, Document doc) throws Exception {
        XPath xp = XPathFactory.newInstance().newXPath();
        return xp.evaluate("count(//" + element + ")", doc);
    }
}
