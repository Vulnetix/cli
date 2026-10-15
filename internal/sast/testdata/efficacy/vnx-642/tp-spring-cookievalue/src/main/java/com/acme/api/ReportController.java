package com.acme.api;

import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class ReportController {

    @GetMapping("/reports")
~>    public ResponseEntity<String> reports(@CookieValue(value = "role", defaultValue = "guest") String role) {
        if (!"admin".equals(role)) {
            return ResponseEntity.status(403).build();
        }
        return ResponseEntity.ok(reportService.all());
    }

    @PostMapping("/session")
    public ResponseEntity<Void> session(Principal p) {
~>        ResponseCookie c = ResponseCookie.from("permissions", perms.of(p)).httpOnly(true).build();
        return ResponseEntity.ok().header("Set-Cookie", c.toString()).build();
    }
}
