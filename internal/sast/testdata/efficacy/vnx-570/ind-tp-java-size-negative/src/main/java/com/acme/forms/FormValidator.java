package com.acme.forms;

import java.util.List;

public class FormValidator {
    public boolean hasErrors(List<String> errors) {
~>        if (errors.size() < 0) {
            return true;
        }
        return !errors.isEmpty();
    }
}
