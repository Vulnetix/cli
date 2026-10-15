package com.acme;

import java.util.ArrayList;
import java.util.List;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/cart")
public class CartController {
  private List<String> items = new ArrayList<>();
  private long total = 0;

  @PostMapping
  public void add(@RequestBody String sku, @RequestParam long price) {
~>    items.add(sku);
~>    this.total += price;
  }

  @GetMapping
  public long total() {
    return total;
  }
}
