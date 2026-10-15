package com.acme.api;

public class Docs {
    /**
     * @deprecated use {@link #login} instead.
     * @Deprecated
     * @GetMapping("/old")
     */
    public void old() {
        log("@Deprecated @GetMapping(\"/old\") is still served");
    }
}
