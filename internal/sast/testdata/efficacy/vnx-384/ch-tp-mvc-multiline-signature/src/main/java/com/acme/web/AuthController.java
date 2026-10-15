package com.acme.web;

import javax.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public String login(
            @RequestParam String username,
            @RequestParam String password,
            HttpSession session) {
        User user = authService.authenticate(username, password);
        if (user == null) {
            return "login";
        }
~>        session.setAttribute("principal", user);
~>        session.setAttribute("role", user.getRole());
        return "redirect:/dashboard";
    }
}
