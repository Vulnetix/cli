package com.acme.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StockController {
    private final StockService stock;

    public StockController(StockService stock) {
        this.stock = stock;
    }

    @GetMapping("/stock/{warehouseId}")
    public Stock get(@PathVariable String warehouseId) {
        return stock.forWarehouse(Integer.parseInt(warehouseId));
    }
}
