package com.acme.pay;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RefundController {
    private final RefundService refunds;

    public RefundController(RefundService refunds) {
        this.refunds = refunds;
    }

    @PostMapping("/refunds")
    public ResponseEntity<String> refund(long orderId) {
        try {
            refunds.refund(orderId);
            return ResponseEntity.ok("refunded");
        } catch (RefundWindowClosedException e) {
            return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(e.getMessage());
        } catch (RuntimeException e) {
            return new ResponseEntity<>("refund failed", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
