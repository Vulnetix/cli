package com.example;

import java.util.Arrays;
import java.util.List;

public class Tags {
    List<String> parse(String header) {
        return Arrays.asList(header.split(","));
    }

    String[] scopes(String s) {
        return s.split(",");
    }
}
