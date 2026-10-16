package com.shop;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import java.util.Map;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Validated
@RestController
public class RawController {

    @PostMapping("/valid")
    public Out v(@Valid @RequestBody InDto dto) { return svc.v(dto); }

    @PostMapping("/raw")
    public void raw(@RequestBody String body) { svc.raw(body); }

    @PostMapping("/map")
    public void map(@RequestBody Map<String, Object> m) { svc.map(m); }

    @PostMapping("/json")
    public void json(@RequestBody JsonNode n) { svc.json(n); }

    @GetMapping("/q")
    public void q(@RequestParam @Size(max = 10) String q) { svc.q(q); }
}
