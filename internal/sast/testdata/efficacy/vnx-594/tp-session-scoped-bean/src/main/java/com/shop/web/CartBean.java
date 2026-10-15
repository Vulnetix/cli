package com.shop.web;

import jakarta.enterprise.context.SessionScoped;
import jakarta.inject.Named;

@Named("cart")
@SessionScoped
~>public class CartBean implements Cloneable {
    private java.util.List<String> items = new java.util.ArrayList<>();
}
