package com.acme.pricing;

public class Lookup {
    public String region(Customer c) {
~>        if (c.getRegion().equals(null)) {
            return "default";
        }
        String code = c.getCode();
~>        boolean missing = code.equals( null );
        return missing ? "?" : code;
    }
}
