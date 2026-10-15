package com.acme.api;

import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.*;

@RestController
public class LookupController {

    @GetMapping("/lookup")
    public Result find(@RequestParam @Size(min = 2, max = 64) String q) {
        return index.find(q);
    }
}
