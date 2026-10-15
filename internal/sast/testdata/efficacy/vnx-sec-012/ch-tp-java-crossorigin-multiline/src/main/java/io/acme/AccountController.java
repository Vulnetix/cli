package io.acme;

import org.springframework.web.bind.annotation.*;

@RestController
~>@CrossOrigin(
    origins = "*",
    maxAge = 3600)
public class AccountController {
    @GetMapping("/account")
    public String account() { return "ok"; }
}
