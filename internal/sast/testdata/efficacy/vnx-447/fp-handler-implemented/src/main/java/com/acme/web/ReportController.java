package com.acme.web;

import org.springframework.web.bind.annotation.*;

@RestController
public class ReportController {

    @GetMapping("/reports/{format}")
    public String render(@PathVariable String format) {
        if (!format.equals("csv")) {
            throw new UnsupportedOperationException("format " + format);
        }
        return service.csv();
    }
}
