package com.acme.auth;

import org.apache.commons.codec.digest.DigestUtils;

public class Avatar {
    String gravatarUrl(String email) {
        String hash = DigestUtils.md5Hex(email.trim().toLowerCase());
        return "https://www.gravatar.com/avatar/" + hash;
    }
}
