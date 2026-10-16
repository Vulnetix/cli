package com.acme.account;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReportController {

    private final ReportService reports;

    public ReportController(ReportService reports) {
        this.reports = reports;
    }

    @GetMapping("/reports/{format}")
    public byte[] render(@PathVariable String format) {
        switch (format) {
            case "csv":
                return reports.csv();
            case "pdf":
                return reports.pdf();
            default:
                throw new UnsupportedOperationException("format " + format);
        }
    }
}
