package com.shop;

import org.springframework.web.bind.annotation.*;

@RestController
public class PlainController {

    @PostMapping("/a")
    public Out a(@RequestBody InDto dto) {
        return svc.a(dto);
    }
}
