package com.shop.admin;

import javax.jws.WebMethod;
import org.springframework.web.bind.annotation.GetMapping;

public class DebugController {

    // @WebMethod
    // public String dumpState() { ... }

    @GetMapping("/debug")
    public String debugInfo() {
        return "ok";
    }

    private String internalHelper() {
        String doc = "@WebMethod public String dumpAll()";
        return doc;
    }

    @WebMethod(exclude = true)
    public String debugCounters() {
        return "0";
    }
}
