package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class DebugController {
    @GetMapping("/debug/heap")
    public ResponseEntity<String> heap(HttpServletRequest request) {
        String clientIp = request.getHeader("X-Forwarded-For");
~>        if (!"127.0.0.1".equals(clientIp)) {
            return ResponseEntity.status(403).build();
        }
        return ResponseEntity.ok(HeapDumper.summary());
    }
}
