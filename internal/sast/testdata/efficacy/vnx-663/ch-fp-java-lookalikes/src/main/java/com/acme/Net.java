package com.acme;

public class Net {
    private static final MacAddress GATEWAY = MacAddress.parse("00:11:22:33:44:55");
    private static final String SIMPLE_DATE_FORMAT = "yyyy-MM-dd";
    // private static SimpleDateFormat legacy;
    private final java.text.SimpleDateFormat perInstance = new java.text.SimpleDateFormat("yyyy");
}
