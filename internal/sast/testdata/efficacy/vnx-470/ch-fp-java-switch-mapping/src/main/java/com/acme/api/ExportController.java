package com.acme.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExportController {
    @GetMapping("/export")
    public String export(@RequestParam String format) throws Exception {
        String impl = switch (format) {
            case "csv" -> "com.acme.export.CsvExporter";
            case "pdf" -> "com.acme.export.PdfExporter";
            default -> throw new IllegalArgumentException(format);
        };
        return Class.forName(impl).getName();
    }

    static Class<?> driver() throws ClassNotFoundException {
        String format = System.getProperty("acme.driver");
        return Class.forName("org.h2.Driver");
    }
}
