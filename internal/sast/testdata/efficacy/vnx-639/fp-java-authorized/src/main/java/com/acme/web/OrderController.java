package com.acme.web;

@RestController
public class OrderController {
    @PreAuthorize("@orderSecurity.isOwner(#orderId, principal)")
    @GetMapping("/orders/{orderId}")
    public Order get(@PathVariable Long orderId) {
        return orderRepository.findById(orderId).orElseThrow();
    }

    @GetMapping("/me/orders/{orderId}")
    public Order mine(@PathVariable Long orderId, Authentication auth) {
        return orderRepository.findByIdAndOwner(orderId, auth.getName());
    }

    public Order internal(Long id) {
        return orderRepository.findById(id).orElseThrow();
    }
}
