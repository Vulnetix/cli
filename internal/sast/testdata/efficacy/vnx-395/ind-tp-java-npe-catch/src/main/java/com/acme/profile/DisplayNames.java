package com.acme.profile;

public final class DisplayNames {
    private DisplayNames() {}

    public static String of(User user) {
        try {
            return user.getProfile().getDisplayName().trim();
~>        } catch (NullPointerException e) {
            return "anonymous";
        }
    }
}
