package com.acme.y;

import com.acme.x.First;

public class Second {
    // private static final String REGION = "eu-west-1";
    /* public static final String REGION = "eu-west-1"; */
    String region() {
        return First.REGION;
    }
}
