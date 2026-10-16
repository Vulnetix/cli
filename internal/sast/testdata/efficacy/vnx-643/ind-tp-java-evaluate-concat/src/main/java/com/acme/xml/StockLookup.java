package com.acme.xml;

import javax.xml.xpath.*;
import org.w3c.dom.*;

public class StockLookup {
    private final XPath xpath = XPathFactory.newInstance().newXPath();

    public NodeList bySupplier(Document doc, Supplier supplier) throws XPathExpressionException {
~>        return (NodeList) xpath.evaluate("//stock[@supplier='" + supplier.getCode() + "']", doc, XPathConstants.NODESET);
    }
}
