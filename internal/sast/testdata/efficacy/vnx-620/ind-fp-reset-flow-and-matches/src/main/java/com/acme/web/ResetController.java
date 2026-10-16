package com.acme.web;

@RestController
public class ResetController {
    @PostMapping("/password/reset")
    public String resetPassword(@RequestBody ResetForm form) {
        User user = tokens.userForToken(form.getToken());
        user.setPassword(encoder.encode(form.getNewPassword()));
        users.save(user);
        return "reset";
    }

    @PostMapping("/account/password")
    public String changePassword(@RequestBody PasswordForm form, Principal p) {
        User user = users.findByName(p.getName());
        if (!passwordEncoder.matches(form.getOldPassword(), user.getPassword())) {
            throw new ForbiddenException();
        }
        user.setPassword(passwordEncoder.encode(form.getNewPassword()));
        return "ok";
    }
}
