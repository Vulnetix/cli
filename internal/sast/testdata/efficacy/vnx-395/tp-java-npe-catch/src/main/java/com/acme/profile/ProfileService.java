package com.acme.profile;

public class ProfileService {
    public String displayName(User user) {
        try {
            return user.getProfile().getDisplayName().trim();
~>        } catch (NullPointerException e) {
            return "anonymous";
        }
    }

    public int age(User user) {
        try {
            return user.getProfile().getAge();
~>        } catch(final java.lang.NullPointerException npe) {
            return -1;
        }
    }

    public String city(User user) {
        try {
            return user.getAddress().getCity();
~>        } catch (IllegalStateException | NullPointerException ex) {
            throw new IllegalArgumentException("address required", ex);
        }
    }
}
