package com.shop;

import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.*;

@RestController
public class SearchController {

    @GetMapping("/search")
    public Result search(
~>            @RequestParam @Size(max = 50) String q) {
        return svc.search(q);
    }
}
