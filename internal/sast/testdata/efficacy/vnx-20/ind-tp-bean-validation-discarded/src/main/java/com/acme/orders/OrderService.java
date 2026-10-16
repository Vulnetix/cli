package com.acme.orders;

import javax.validation.Validator;
import org.springframework.stereotype.Service;

@Service
public class OrderService {

    private final Validator validator;
    private final OrderRepository repository;

    public OrderService(Validator validator, OrderRepository repository) {
        this.validator = validator;
        this.repository = repository;
    }

    public Order place(Order order) {
~>        validator.validate(order);
        order.setStatus(OrderStatus.PLACED);
        return repository.save(order);
    }
}
