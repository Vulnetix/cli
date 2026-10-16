package com.acme.web;

public class EmployeeServlet extends javax.servlet.http.HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        com.acme.support.RequestFacade facade =
                new com.acme.support.RequestFacade(request);
        String param = facade.fixed("id");
        String bar = "";
        if (param != null) {
            bar =
                    new String(
                            Codec.decode(
                                    Codec.encode(
                                            param.getBytes())));
        }
        javax.xml.xpath.XPathFactory xpf = javax.xml.xpath.XPathFactory.newInstance();
        javax.xml.xpath.XPath xp = xpf.newXPath();
        String expression = "/Employees/Employee[@emplid='" + bar + "']";
        Object o = xp.compile(expression).evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);
    }
}
