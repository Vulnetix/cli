package com.acme.auth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

    @GetMapping("/login/success")
    public String afterLogin(@RequestParam("redirectUrl") String redirectUrl) {
~>        if (redirectUrl.startsWith("https://app.example.com")) {
            return "redirect:" + redirectUrl;
        }
        return "redirect:/home";
    }
}
