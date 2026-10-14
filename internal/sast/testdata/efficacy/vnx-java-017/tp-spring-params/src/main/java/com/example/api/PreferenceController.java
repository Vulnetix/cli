package com.example.api;

import java.io.IOException;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PreferenceController {

    @GetMapping("/prefs/{theme}")
    public void setTheme(@PathVariable("theme") String theme,
                         @RequestParam(value = "lang", required = false) String lang,
                         HttpServletResponse response) throws IOException {
~>        response.setHeader("X-Theme", theme);
~>        response.addHeader("Set-Cookie", "lang=" + lang + "; Path=/");
    }

    @GetMapping("/go")
    public void go(@RequestHeader("X-Return-To") String returnTo, HttpServletResponse httpResponse) throws IOException {
~>        httpResponse.sendRedirect(returnTo);
    }
}
