package com.acme.shop;

import java.io.Serializable;
import javax.persistence.Embeddable;

@Embeddable
public class Address
        implements Serializable {
    private String street;
    private String city;
}
