package com.acme.xml;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class FieldReader {
    public String read(Document doc, HttpServletRequest request) throws XPathExpressionException {
        String id = request.getParameter("id");
        if (!id.matches("[0-9]{1,9}")) {
            throw new IllegalArgumentException("bad id");
        }
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate("/orders/order[@id='" + id + "']/total", doc);
    }
}
