package com.acme.geo;

public class AddressValidator {
    public boolean hasCity(User user) {
~>        if (user.address != null & user.address.city.isEmpty()) {
            return false;
        }
        return true;
    }
}
