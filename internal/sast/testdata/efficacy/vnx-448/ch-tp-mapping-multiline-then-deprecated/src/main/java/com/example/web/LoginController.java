package com.example.web;

import org.springframework.web.bind.annotation.*;

@Controller
public class LoginController {

    @RequestMapping(
        value = "/legacy/login",
        method = RequestMethod.POST)
~>    @Deprecated(since = "3.2", forRemoval = true)
    public String legacyLogin(@RequestParam String user, @RequestParam String password) {
        return auth.plainLogin(user, password) ? "home" : "login";
    }
}
