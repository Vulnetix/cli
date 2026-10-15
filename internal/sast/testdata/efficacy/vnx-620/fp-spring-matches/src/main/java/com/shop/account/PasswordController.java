package com.shop.account;

@RestController
public class PasswordController {
    @PostMapping("/account/change-password")
    public void changePassword(@RequestBody ChangePasswordForm form, Principal principal) {
        User user = users.findByUsername(principal.getName());
        if (!passwordEncoder.matches(form.getOldPassword(), user.getPassword())) {
            throw new BadCredentialsException("current password is wrong");
        }
        user.setPassword(passwordEncoder.encode(form.getNewPassword()));
        users.save(user);
    }
}
