package com.shop.cart;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.context.annotation.RequestScope;

@Controller
@RequestScope
public class CheckoutController {
    private String customer;

    @PostMapping("/checkout")
    public String checkout(HttpServletRequest request) {
        customer = request.getRemoteUser();
        return "redirect:/thanks?c=" + customer;
    }
}
