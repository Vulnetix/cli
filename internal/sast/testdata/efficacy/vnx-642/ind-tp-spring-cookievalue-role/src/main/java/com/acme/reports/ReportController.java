package com.acme.reports;

import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ReportController {
    private final ReportService reports;

    public ReportController(ReportService reports) {
        this.reports = reports;
    }

    @GetMapping("/reports")
~>    public ResponseEntity<List<Report>> list(@CookieValue("user_role") String userRole) {
        return ResponseEntity.ok(reports.visibleTo(userRole));
    }
}
