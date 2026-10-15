package app;

import org.springframework.web.bind.annotation.*;

@RestController
public class OrderController {
    @GetMapping("/orders")
    public Order get(@RequestParam("id") String orderId, @RequestHeader String limit) {
~>        return repo.find(Integer.valueOf(orderId), Integer.parseInt(limit));
    }

    public void update(HttpServletRequest request) {
        String qty = request.getParameter("qty");
        log.info("qty {}", qty);
~>        double amount = Double.parseDouble(qty);
        repo.save(amount);
    }
}
