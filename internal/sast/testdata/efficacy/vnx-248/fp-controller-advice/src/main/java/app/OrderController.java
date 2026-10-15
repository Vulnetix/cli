package app;

@RestController
public class OrderController {
    @GetMapping("/orders")
    public Order get(@RequestParam("id") String orderId) {
        return repo.find(Integer.valueOf(orderId));
    }

    @ExceptionHandler(NumberFormatException.class)
    public ResponseEntity<String> badNumber() {
        return ResponseEntity.badRequest().build();
    }
}
