package com.acme;

import javax.servlet.http.Cookie;

public class PrefsController {
    Cookie layout(String value) {
        Cookie c = new Cookie("keyboard_layout", value);
        Cookie m = new Cookie("monkey_mode", "on");
        return c;
    }
}
