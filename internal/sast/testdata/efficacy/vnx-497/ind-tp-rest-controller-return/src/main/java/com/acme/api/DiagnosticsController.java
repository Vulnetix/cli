package com.acme.api;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal")
public class DiagnosticsController {

    @GetMapping("/cwd")
    public String workingDirectory() {
        String dir = System.getProperty("user.dir");
~>        return "cwd=" + dir;
    }

    @GetMapping("/env")
    public ResponseEntity<Map<String, String>> env() {
~>        return ResponseEntity.ok(System.getenv());
    }

    @GetMapping("/vm")
    public ResponseEntity<String> vm() {
        RuntimeMXBean runtime = ManagementFactory.getRuntimeMXBean();
~>        return ResponseEntity.ok(runtime.getVmName() + " " + runtime.getVmVersion());
    }
}
