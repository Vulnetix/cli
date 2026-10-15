package com.acme.api;

@RestController
@RequestScope
public class ContextController {
    private String tenant;

    @GetMapping("/ctx")
    public String ctx(HttpServletRequest request) {
        tenant = request.getHeader("X-Tenant");
        return tenant;
    }
}
