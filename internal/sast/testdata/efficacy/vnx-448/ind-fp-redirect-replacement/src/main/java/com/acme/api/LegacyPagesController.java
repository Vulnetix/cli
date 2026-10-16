package com.acme.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LegacyPagesController {

    @Deprecated
    @GetMapping("/settings/profile.do")
    public String oldProfilePage() {
        return "redirect:/settings/profile";
    }
}
