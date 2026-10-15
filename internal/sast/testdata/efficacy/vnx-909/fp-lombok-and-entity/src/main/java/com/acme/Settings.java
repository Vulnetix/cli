package com.acme;

import lombok.Setter;

@Setter
public class Settings {
    private String theme;

    public String css() {
        return theme.toLowerCase() + ".css";
    }
}
