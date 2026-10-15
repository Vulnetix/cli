package com.acme.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExportController {
    @GetMapping("/export/{format}")
    public String export(@PathVariable("format") String format) throws Exception {
~>        Class<?> exporter = Class.forName(
                "com.acme.export." + format + "Exporter");
        return exporter.getName();
    }
}
