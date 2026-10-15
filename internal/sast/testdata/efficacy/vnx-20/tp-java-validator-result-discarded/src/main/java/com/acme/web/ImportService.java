package com.acme.web;

import javax.validation.Validator;

public class ImportService {
    private final Validator validator;
    private final Repository repo;

    public ImportService(Validator validator, Repository repo) {
        this.validator = validator;
        this.repo = repo;
    }

    public void importOrder(OrderDto order) {
~>        validator.validate(order);
        repo.save(order);
    }

    public void importCustomer(CustomerDto customer) {
~>        this.validator.validate(customer, Default.class);
        repo.save(customer);
    }
}
