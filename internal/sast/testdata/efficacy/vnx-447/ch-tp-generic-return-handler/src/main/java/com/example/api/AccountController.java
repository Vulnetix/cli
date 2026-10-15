package com.example.api;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/account")
public class AccountController {

    @PostMapping("/export")
~>    public ResponseEntity<Map<String, Object>> exportData(@RequestParam String format) {
        throw new UnsupportedOperationException("export is coming soon");
    }
}
