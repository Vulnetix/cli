package com.acme.xml;

import javax.xml.xpath.*;

public class BinIndex {
    XPathExpression find(XPath xpath, Bin bin) throws Exception {
        String label = bin.getLabel();
        String path = "//bin[@label='" + label + "']";
~>        return xpath.compile(path);
    }
}
