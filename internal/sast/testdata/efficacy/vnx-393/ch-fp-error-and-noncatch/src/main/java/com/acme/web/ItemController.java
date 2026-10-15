package com.acme.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class ItemController {
    public ResponseEntity<Item> get(long id) {
        try {
            Item item = repo.find(id);
            return ResponseEntity.ok(item);
        } catch (NotFoundException e) {
            return ResponseEntity.notFound().build();
        } catch (RuntimeException e) {
            return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .build();
        } finally {
            metrics.done();
        }
    }

    public boolean isTokenValid(String token) {
        try {
            parser.parse(token);
            return true;
        } catch (ParseException e) {
            return false;
        }
    }

    public boolean isEmptyQueue() {
        try {
            return queue.size() == 0;
        } catch (IllegalStateException e) {
            return true;
        }
    }
}
