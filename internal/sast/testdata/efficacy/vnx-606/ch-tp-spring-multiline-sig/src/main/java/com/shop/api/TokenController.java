package com.shop.api;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenController {

    @GetMapping("/tokens")
    public List<String> tokens(
            @RequestParam(name = "n", defaultValue = "1") int n) {
        List<String> out = new ArrayList<>();
~>        for (int i = 0; i <= n; i++) {
            out.add(UUID.randomUUID().toString());
        }
        return out;
    }
}
