package com.acme.api;

import java.io.StringReader;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    @PostMapping(value = "/orders", consumes = "application/xml")
    public String create(@RequestBody String body) throws Exception {
        Unmarshaller u = JAXBContext.newInstance(Order.class).createUnmarshaller();
~>        Order order = (Order) u.unmarshal(new StringReader(body));
        return order.getId();
    }
}
