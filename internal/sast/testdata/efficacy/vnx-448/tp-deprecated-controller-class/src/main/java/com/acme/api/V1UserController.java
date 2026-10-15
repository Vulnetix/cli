package com.acme.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

~>@Deprecated
@Controller
@RequestMapping("/api/v1/users")
public class V1UserController {

    @GetMapping("/{id}")
    public String show(@PathVariable long id) {
        return "users/show";
    }
}
