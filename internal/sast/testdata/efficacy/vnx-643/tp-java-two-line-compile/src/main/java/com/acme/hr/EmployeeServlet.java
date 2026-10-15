package com.acme.hr;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

public class EmployeeServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String bar = request.getParameter("id");
        XPath xp = XPathFactory.newInstance().newXPath();
        String expression = "/Employees/Employee[@emplid='" + bar + "']";
~>        XPathExpression expr = xp.compile(expression);
~>        String result = xp.evaluate(expression, xmlDocument);
        String query = String.format("/Employees/Employee[@name='%s']", request.getParameter("name"));
~>        Object nodes = xp.evaluate(query, xmlDocument, XPathConstants.NODESET);
        response.getWriter().println(result);
    }
}
