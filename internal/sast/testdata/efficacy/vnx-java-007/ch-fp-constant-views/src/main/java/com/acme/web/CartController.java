package com.acme.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class CartController {
    private org.slf4j.Logger log;

    @PostMapping("/cart/add")
    public String add(@RequestParam("sku") String sku) {
        log.info("redirecting after add of " + sku);
        // return "redirect:" + sku;
        return "redirect:/cart";
    }
}
