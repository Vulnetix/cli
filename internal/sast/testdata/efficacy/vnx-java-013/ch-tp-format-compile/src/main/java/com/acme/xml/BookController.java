package com.acme.xml;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;
import org.w3c.dom.Node;

@RestController
public class BookController {
    private final Document catalog;
    private final XPath xp = XPathFactory.newInstance().newXPath();

    public BookController(Document catalog) {
        this.catalog = catalog;
    }

    @GetMapping("/books")
    public String byIsbn(@RequestParam("isbn") String isbn) throws Exception {
~>        XPathExpression e = xp.compile(String.format("//book[@isbn='%s']/title", isbn));
        Node n = (Node) e.evaluate(catalog, XPathConstants.NODE);
        return n == null ? "" : n.getTextContent();
    }
}
