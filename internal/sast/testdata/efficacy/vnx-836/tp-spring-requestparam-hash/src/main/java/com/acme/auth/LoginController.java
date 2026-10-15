package com.acme.auth;

@RestController
public class LoginController {
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username,
                                        @RequestParam("pwHash") String clientHash) {
        Account a = repo.findByUsername(username);
~>        if (MessageDigest.isEqual(a.getPasswordHash().getBytes(), clientHash.getBytes())) {
            return ResponseEntity.ok(tokens.issue(a));
        }
        return ResponseEntity.status(401).build();
    }
}
