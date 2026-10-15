package com.shop.web;

import javax.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class OrderController {
    private final OrderService orders;

    public OrderController(OrderService orders) {
        this.orders = orders;
    }

    @PostMapping("/orders")
    public String create(
            @Valid @ModelAttribute("order") OrderForm order,
~>            BindingResult errors) {
        orders.place(order.toOrder());
        return "redirect:/orders";
    }

    @PostMapping("/orders/cancel")
    public String cancel(@Valid CancelForm form, BindingResult br) {
        if (br.hasErrors()) {
            return "orders/cancel";
        }
        orders.cancel(form.getId());
        return "redirect:/orders";
    }
}
