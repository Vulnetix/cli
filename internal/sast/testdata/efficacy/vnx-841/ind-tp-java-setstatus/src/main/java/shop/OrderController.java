package shop;

@RestController
public class OrderController {
    @PostMapping("/orders/{id}/update")
    public Order update(@PathVariable long id, @RequestParam String status) {
        Order order = orders.get(id);
~>        order.setStatus(status);
        return orders.save(order);
    }
}
