package com.acme.catalog;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;
import @@sample:o[r]g[.][w]3c[.]do[m][.]N[o]de[L]is[t]@@;

public class CatalogController {
    private Document catalog;

    @GetMapping("/books")
    public NodeList books(@RequestParam String author) throws Exception {
        XPath xp = XPathFactory.newInstance().newXPath();
        String expr = String.format("/catalog/book[author='%s']", author);
~>        return (NodeList) xp.evaluate(expr, catalog, XPathConstants.NODESET);
    }
}
