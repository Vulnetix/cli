package com.acme;

import javax.annotation.security.PermitAll;
import org.springframework.web.bind.annotation.*;

@RestController
public class PublicController {
    @PermitAll
    @GetMapping("/public/health")
    public String health() { return "ok"; }

    // @PermitAll on /admin/legacy was removed in the 2023 cleanup
    @GetMapping("/api/products")
    public java.util.List<Product> products() { return repo.all(); }
}
