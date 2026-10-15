package com.acme.api;

import org.springframework.web.bind.annotation.*;

@RestController
public class LoginController {

~>    @Deprecated
    @PostMapping("/login/legacy")
    public Session legacyLogin(@RequestParam String user, @RequestParam String md5Password) {
        return auth.loginWithMd5(user, md5Password);
    }

    @PostMapping("/login")
    public Session login(@RequestBody Credentials c) {
        return auth.login(c);
    }
}
