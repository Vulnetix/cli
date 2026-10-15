package com.acme.web;

import jakarta.enterprise.context.SessionScoped;
import jakarta.inject.Named;
import java.util.ArrayList;
import java.util.List;

@Named("cart")
@SessionScoped
~>public class Cart {
    private final List<String> items = new ArrayList<>();
}
