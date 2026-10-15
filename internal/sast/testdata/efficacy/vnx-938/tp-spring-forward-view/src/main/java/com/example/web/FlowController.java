package com.example.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class FlowController {

    @GetMapping("/continue")
    public String next(@RequestParam("step") String step) {
~>        return "forward:" + step;
    }

    @GetMapping("/resume")
    public ModelAndView resume(@RequestParam(name = "to", required = false) final String to) {
~>        return new ModelAndView("forward:/" + to);
    }
}
