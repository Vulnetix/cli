package com.acme;

import org.springframework.web.bind.annotation.*;

@RestController
public class LimitController {
    @GetMapping("/limit")
    public int limit(HttpServletRequest request) {
~>      int limit = Integer.decode(request.getParameter("limit"));
        return Math.min(limit, 500);
    }
}
