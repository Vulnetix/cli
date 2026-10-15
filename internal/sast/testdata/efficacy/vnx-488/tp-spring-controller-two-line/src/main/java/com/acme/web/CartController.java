package com.acme.web;

@RestController
public class CartController {
    private Cart currentCart;
    private static String lastUser;

    @GetMapping("/cart")
    public Cart cart(HttpServletRequest req) {
        String user = req.getRemoteUser();
~>        lastUser = user;
~>        currentCart = repo.findByOwner(req.getUserPrincipal().getName());
        return currentCart;
    }
}
