package com.acme.web;

import java.net.URI;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ShortLinks {
    @GetMapping("/l")
    public void link(@RequestParam String dest, HttpServletResponse response) {
        response.setStatus(302);
~>        response.setHeader("Location", dest);
    }

    @GetMapping("/r")
    public ResponseEntity<Void> resolve(@RequestHeader("X-Return") String back) {
~>        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(back)).build();
    }

    @GetMapping("/h")
    public ResponseEntity<Void> header(@RequestParam String u) {
~>        return ResponseEntity.status(HttpStatus.FOUND).header(HttpHeaders.LOCATION, u).build();
    }
}
