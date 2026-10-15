package io.acme;

import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(
    origins = {"https://app.acme.io"},
    allowCredentials = "true")
public class ReportController {
    @GetMapping("/reports")
    public String reports() { return "ok"; }
}
