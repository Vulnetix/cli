package io.acme;

import org.springframework.http.ResponseCookie;

public class SafeLoginController {
    public String login(String user) {
        ResponseCookie a = ResponseCookie.from("SESSION", sessions.create(user)).httpOnly(true).secure(true).build();
        ResponseCookie b = ResponseCookie.from("refresh_token", tokens.refresh(user))
            .httpOnly(true)
            .secure(true)
            .sameSite("Strict")
            .build();
        ResponseCookie theme = ResponseCookie.from("theme", "dark").path("/").build();
        return a.toString() + b + theme;
    }
}
