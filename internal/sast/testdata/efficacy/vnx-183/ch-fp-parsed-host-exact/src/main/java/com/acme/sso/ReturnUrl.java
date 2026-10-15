package com.acme.sso;

import java.net.URI;

public class ReturnUrl {
    public String resolve(String returnTo) {
        String host = URI.create(returnTo).getHost();
        if ("acme.com".equals(host) || URI.create(returnTo).getHost().endsWith(".acme.com")) {
            return "redirect:" + returnTo;
        }
        return "redirect:/";
    }
}
