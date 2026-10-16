package com.acme.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ApiErrorHandler {
    @ExceptionHandler(NumberFormatException.class)
    public ResponseEntity<String> badNumber(NumberFormatException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("invalid number");
    }
}
