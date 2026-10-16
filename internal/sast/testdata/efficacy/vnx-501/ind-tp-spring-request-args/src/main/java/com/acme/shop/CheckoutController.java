package com.acme.shop;

import javax.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class CheckoutController {

    @PostMapping("/cart/discount")
    public String applyDiscount(@RequestParam("code") String code, HttpSession session) {
~>        session.setAttribute("discountCode", code);
        return "redirect:/cart";
    }

    @PostMapping("/store/{storeId}/select")
    public String selectStore(@PathVariable String storeId,
                              @CookieValue(name = "aff", required = false) String affiliate,
                              HttpSession session) {
~>        session.setAttribute("storeId", storeId);
~>        session.setAttribute("affiliate", affiliate);
        return "redirect:/store";
    }
}
