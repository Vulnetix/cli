package com.shop;

public class Notes {
    public String join(List<String> parts) {
        String joined = String.join(",", parts);
        for (String part : parts) {
            // joined += part;  is quadratic, so String.join is used instead
            log.debug("joined += part");
        }
        return joined;
    }
}
