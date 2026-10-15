package com.acme.web

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam

@Controller
class HomeController {
    @GetMapping("/start")
    fun start(@RequestParam tab: String): String {
        val safeTab = if (tab in setOf("a", "b")) tab else "a"
        return "redirect:/home?tab=a"
    }
}
