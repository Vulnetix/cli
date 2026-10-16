package com.acme.web;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

@Controller
public class ApiController {

    @GetMapping(value = "/api/name", produces = "application/json")
    @ResponseBody
    public String json(@RequestParam String name) {
        return "{\"name\": \"" + name + "\"}";
    }

    @GetMapping("/view")
    public String view(@RequestParam String page, Model model) {
        model.addAttribute("page", page);
        return page;
    }

    @GetMapping("/plain")
    public ResponseEntity<String> plain(@RequestParam("msg") String msg) {
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(msg);
    }

    @GetMapping(value = "/safe", produces = "text/html")
    @ResponseBody
    public String safe(@RequestParam String name) {
        return "<h1>" + HtmlUtils.htmlEscape(name) + "</h1>";
    }
}
