package com.acme;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CheckoutService {
    private final CartRepository cartRepository;
    private final OrderRepository orderRepository;
    private final JdbcTemplate jdbcTemplate;

    CheckoutService(CartRepository cartRepository, OrderRepository orderRepository, JdbcTemplate jdbcTemplate) {
        this.cartRepository = cartRepository;
        this.orderRepository = orderRepository;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
~>    public Order checkout(long userId) {
        Cart cart = cartRepository.findByUserId(userId);
        Integer stock = jdbcTemplate.queryForObject(
            "SELECT stock FROM item WHERE id = ?", Integer.class, cart.itemId());
        jdbcTemplate.update("UPDATE item SET stock = stock - 1 WHERE id = ?", cart.itemId());
        Order order = orderRepository.save(new Order(cart));
        cartRepository.delete(cart);
        return order;
    }

    public long pending() {
        return orderRepository.countByStatus("PENDING");
    }
}
