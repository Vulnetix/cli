package com.acme.shop;

@jakarta.persistence.Entity(name = "Customer")
~>public final class Customer {
    @jakarta.persistence.Id
    private Long id;
    private String email;
}
