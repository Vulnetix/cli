package com.acme.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExportController {

    @GetMapping("/export")
    public String export(@RequestParam("format") String format) throws Exception {
~>        Class<?> type = Class.forName("com.acme.export." + format + "Exporter");
        Exporter exporter = (Exporter) type.getDeclaredConstructor().newInstance();
        return exporter.run();
    }

    @GetMapping("/render")
    public String render(@RequestParam String renderer) throws Exception {
~>        Object r = Class.forName(String.format("com.acme.render.%s", renderer)).getDeclaredConstructor().newInstance();
        return r.toString();
    }
}
