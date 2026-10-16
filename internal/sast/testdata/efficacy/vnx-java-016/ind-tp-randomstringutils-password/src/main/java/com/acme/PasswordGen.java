package com.acme;

import org.apache.commons.lang3.RandomStringUtils;

public class PasswordGen {
    public String temporaryPassword() {
~>        String password = RandomStringUtils.randomAlphanumeric(12);
        return password;
    }
}
