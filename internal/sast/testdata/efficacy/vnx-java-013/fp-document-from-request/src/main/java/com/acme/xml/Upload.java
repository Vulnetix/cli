package com.acme.xml;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

public class Upload {
    String title(HttpServletRequest request) throws Exception {
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(request.getInputStream());
        XPath xp = XPathFactory.newInstance().newXPath();
        return xp.evaluate("/book/title", doc);
    }
}
