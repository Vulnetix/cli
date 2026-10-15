package com.acme.api;

import java.io.StringReader;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;
import org.xml.sax.InputSource;

@RestController
public class ImportController {

    @PostMapping(value = "/import", consumes = "application/xml")
    public int importOrders(@RequestBody String payload) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder db = dbf.newDocumentBuilder();
~>        Document doc = db.parse(new InputSource(new StringReader(payload)));
        return doc.getElementsByTagName("order").getLength();
    }
}
