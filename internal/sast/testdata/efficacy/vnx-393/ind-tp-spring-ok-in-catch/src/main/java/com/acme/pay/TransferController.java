package com.acme.pay;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TransferController {
    private final TransferService transfers;

    public TransferController(TransferService transfers) {
        this.transfers = transfers;
    }

    @PostMapping("/transfers")
    public ResponseEntity<String> transfer(@RequestBody TransferRequest req) {
        try {
            transfers.execute(req);
            return ResponseEntity.ok("done");
        } catch (InsufficientFundsException e) {
~>            return ResponseEntity.ok("transfer failed: " + e.getMessage());
        }
    }
}
