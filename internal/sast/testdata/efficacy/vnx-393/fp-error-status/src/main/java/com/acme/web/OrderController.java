package com.acme.web;

import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class OrderController {
    public ResponseEntity<String> place(Order o) {
        try {
            service.place(o);
            return ResponseEntity.ok("placed");
        } catch (ValidationException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    public void legacy(HttpServletResponse resp) throws java.io.IOException {
        try {
            service.legacy();
            resp.setStatus(HttpServletResponse.SC_OK);
        } catch (IllegalStateException e) {
            resp.sendError(HttpServletResponse.SC_CONFLICT, "conflict");
        }
        resp.setStatus(200);
    }

    public ResponseEntity<Void> idempotentDelete(long id) {
        try {
            service.delete(id);
        } catch (NotFoundException e) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return ResponseEntity.ok().build();
    }
}
