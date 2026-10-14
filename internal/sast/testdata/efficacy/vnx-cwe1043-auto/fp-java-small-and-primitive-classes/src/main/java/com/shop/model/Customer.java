package com.shop.model;

public class Customer {
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String phone;
    private String street;
    private String city;
    private String postcode;
    private String country;
    private Integer loyaltyPoints;
    private Boolean active;
    private int version;
    private long createdAt;
    private double balance;
    private Address address;
    private List<Order> orders;
    private Account account;

    public String getEmail() { return email; }
}
