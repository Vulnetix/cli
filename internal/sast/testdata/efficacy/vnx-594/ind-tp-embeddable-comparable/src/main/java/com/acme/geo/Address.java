package com.acme.geo;

import java.util.Comparator;
import javax.persistence.Embeddable;

@Embeddable
~>public class Address
        implements Comparable<Address> {

    private String street;
    private String city;
    private String postcode;

    @Override
    public int compareTo(Address other) {
        return Comparator.comparing((Address a) -> a.postcode)
                .thenComparing(a -> a.street)
                .compare(this, other);
    }
}
