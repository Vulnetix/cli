package com.acme;

import javax.xml.xpath.*;
import org.w3c.dom.Document;

public class FixedXPath {
    private static final String ADMIN = "//user[role='admin']/name";

    public String admin(Document doc) throws XPathExpressionException {
        return XPathFactory.newInstance().newXPath().evaluate(ADMIN, doc);
    }
}
