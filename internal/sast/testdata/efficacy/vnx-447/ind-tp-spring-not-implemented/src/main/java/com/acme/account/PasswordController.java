package com.acme.account;

import org.apache.commons.lang3.NotImplementedException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PasswordController {

    @PostMapping("/account/password/reset")
~>    public ResponseEntity<Void> resetPassword(@RequestBody ResetRequest request) {
        throw new NotImplementedException("password reset is coming in 3.2");
    }
}
