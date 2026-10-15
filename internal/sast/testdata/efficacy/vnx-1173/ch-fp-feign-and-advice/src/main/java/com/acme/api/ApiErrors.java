package com.acme.api;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice
public class ApiErrors {
    // Handlers below do not bind request parameters; @RequestParam @NotBlank would only matter in a controller.
    @ExceptionHandler(IllegalStateException.class)
    public Error onState(IllegalStateException e) {
        return new Error(e.getMessage());
    }
}
