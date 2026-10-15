package com.acme.sso;

import java.net.URI;

public class ReturnUrl {
    public String resolve(String returnTo) {
~>        if (URI.create(returnTo).getHost().endsWith("acme.com")) {
            return "redirect:" + returnTo;
        }
        return "redirect:/";
    }
}
