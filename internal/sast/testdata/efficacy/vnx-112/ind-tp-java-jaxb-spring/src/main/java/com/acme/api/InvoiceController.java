package com.acme.api;

import java.io.StringReader;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InvoiceController {
    private final JAXBContext context;

    public InvoiceController() throws JAXBException {
        this.context = JAXBContext.newInstance(Invoice.class);
    }

    @PostMapping(path = "/invoices", consumes = MediaType.APPLICATION_XML_VALUE)
    public String create(@RequestBody String body) throws JAXBException {
        Unmarshaller unmarshaller = context.createUnmarshaller();
~>        Invoice invoice = (Invoice) unmarshaller.unmarshal(new StringReader(body));
        return invoice.getNumber();
    }
}
