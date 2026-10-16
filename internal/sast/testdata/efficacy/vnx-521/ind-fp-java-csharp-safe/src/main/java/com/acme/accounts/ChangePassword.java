package com.acme.accounts;

import jakarta.validation.constraints.Size;

public class ChangePassword {

    @Size(min = 2, max = 40)
    private String displayName;

    @Size(min = 12, max = 128)
    private String password;

    public boolean exceedsMaximum() {
        return password.length() > 30;
    }

    public boolean isPinShort(String pin) {
        return pin.length() < 4;
    }
}
