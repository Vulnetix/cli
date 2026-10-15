package com.acme.api;

@RestController
@RequestMapping("/api")
public class TenantController {
    private String tenant;

    @GetMapping("/items")
    public List<Item> items(HttpServletRequest request) {
~>        this.tenant = request.getHeader("X-Tenant");
        return repo.findAll(tenant);
    }
}
