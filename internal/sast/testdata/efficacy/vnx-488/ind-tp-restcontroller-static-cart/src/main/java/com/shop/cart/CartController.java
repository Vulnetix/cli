package com.shop.cart;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CartController {
    private static HttpSession lastSession;
    private String couponCode;

    private final CartService carts;

    public CartController(CartService carts) {
        this.carts = carts;
    }

    @GetMapping("/cart")
    public Cart cart(HttpServletRequest request) {
~>        lastSession = request.getSession();
~>        couponCode = request.getParameter("coupon");
        return carts.load(lastSession.getId(), couponCode);
    }
}
