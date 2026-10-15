package com.acme.web;

import java.util.regex.Pattern;

public class InputValidator {

    private static final Pattern ORDER_ID = Pattern.compile("^[0-9]{6,12}");

    public boolean validOrder(String id) {
~>        return ORDER_ID.matcher(id).find();
    }

    public boolean validName(String name) {
~>        return Pattern.compile("[A-Za-z]+$").matcher(name).find();
    }

    public boolean validCode(String code) {
~>        return Pattern.compile("^\\w{4}").matcher(code).lookingAt();
    }
}
