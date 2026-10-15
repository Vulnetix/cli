package com.example.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ReportController {

    @Deprecated
    @GetMapping("/reports/old")
    public String oldReports() {
        return "redirect:/v2/reports";
    }
}
