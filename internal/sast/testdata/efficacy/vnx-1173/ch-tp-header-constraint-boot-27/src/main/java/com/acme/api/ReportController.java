package com.acme.api;

import javax.validation.constraints.Max;
import javax.validation.constraints.Pattern;
import org.springframework.web.bind.annotation.*;

@RestController
public class ReportController {

    @GetMapping("/reports/{name}")
    public Report get(
~>            @PathVariable("name") @Pattern(regexp = "[a-z0-9-]{1,40}") String name,
~>            @RequestParam(defaultValue = "50") @Max(500) int limit,
~>            @RequestHeader("X-Tenant") @Pattern(regexp = "[a-z]+") String tenant) {
        return reports.load(tenant, name, limit);
    }
}
