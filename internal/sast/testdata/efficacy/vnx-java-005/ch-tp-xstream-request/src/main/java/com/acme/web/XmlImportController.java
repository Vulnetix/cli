package com.acme.web;

import com.thoughtworks.xstream.XStream;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class XmlImportController {
    private final XStream xstream = new XStream();

    @PostMapping("/import")
    public String importXml(@RequestBody String body) {
~>        Object order = xstream.fromXML(body);
        return order.toString();
    }
}
