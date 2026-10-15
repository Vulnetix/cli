package com.acme.auth;

import java.time.Duration;
import org.springframework.http.ResponseCookie;

public class Cookies {
    public ResponseCookie session(String token) {
        return ResponseCookie.from("SESSION", token).httpOnly(true).maxAge(Duration.ofMinutes(30)).build();
    }

    public ResponseCookie theme(String theme) {
        return ResponseCookie.from("theme", theme).maxAge(Duration.ofDays(365)).build();
    }

    public ResponseCookie clear() {
        return ResponseCookie.from("jwt", "").maxAge(0).build();
    }
}
