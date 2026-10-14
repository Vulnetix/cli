package com.acme.xml;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;

@RestController
public class LoginCheck {
    private final XPath xpath = XPathFactory.newInstance().newXPath();
    private Document users;

    @PostMapping("/login")
    public boolean login(@RequestParam String user, @RequestParam String pass) throws Exception {
~>        XPathExpression expr = xpath.compile("//user[name/text()='" + user
                + "' and password/text()='" + pass + "']");
        return (Boolean) expr.evaluate(users, XPathConstants.BOOLEAN);
    }

    @GetMapping("/node")
    public Object node(@RequestHeader("X-Path") String path) throws Exception {
~>        return xpath.evaluate(path, users, XPathConstants.NODE);
    }
}
