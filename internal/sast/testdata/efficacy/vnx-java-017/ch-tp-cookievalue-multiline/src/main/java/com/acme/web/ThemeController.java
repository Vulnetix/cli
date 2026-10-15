package com.acme.web;

import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ThemeController {
    @GetMapping("/theme")
    public String theme(@CookieValue(name = "theme", defaultValue = "light") String theme,
                        HttpServletResponse response) {
~>        response.setHeader(
            "X-Theme",
            theme);
        return "ok";
    }
}
