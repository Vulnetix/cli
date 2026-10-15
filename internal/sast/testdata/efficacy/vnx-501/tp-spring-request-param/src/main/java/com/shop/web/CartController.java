package com.shop.web;

import javax.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CartController {
    @PostMapping("/cart/discount")
    public String applyDiscount(@RequestParam("code") String code, HttpSession session) {
~>        session.setAttribute("discountCode", code);
        return "applied";
    }
}
