package com.acme.catalog;

import java.util.List;
import org.dom4j.Document;
import org.dom4j.Node;

public class ProductRepository {
    private final Document doc;

    public ProductRepository(Document doc) {
        this.doc = doc;
    }

    public Node bySku(OrderLine line) {
~>        return doc.selectSingleNode(String.format("//product[sku='%s']/price", line.getSku()));
    }
}
