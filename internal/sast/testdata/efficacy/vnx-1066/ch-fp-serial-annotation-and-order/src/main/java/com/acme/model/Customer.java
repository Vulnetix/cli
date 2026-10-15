package com.acme.model;

import java.io.Serial;
import java.io.Serializable;

public class Customer implements Serializable {
    private String name;

    /** Stream version. */
    @Serial
    private static final long serialVersionUID = @@sample:[-][4]21[1]25[0]98[2]63[4]51[2]37[7]L@@;

    public static class Address implements Serializable {
        @Serial private static final long serialVersionUID = 2L;
        private String street;
    }
}
