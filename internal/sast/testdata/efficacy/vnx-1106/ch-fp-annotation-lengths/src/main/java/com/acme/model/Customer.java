package com.acme.model;

import javax.persistence.Column;
import javax.validation.constraints.Size;

public class Customer {
    @Column(length = 120)
    private String firstName;

    @Column(length = 120)
    private String lastName;

    @Size(max = 120)
    @Column(length = 120)
    private String email;
}
