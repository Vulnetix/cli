package com.acme;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.*;
import org.w3c.dom.Document;

public class BodyDoc {
    public String title(HttpServletRequest request) throws Exception {
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(request.getInputStream());
        return XPathFactory.newInstance().newXPath().evaluate("/order/title", doc);
    }
}
