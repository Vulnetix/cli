package com.acme.web;

public class OrderController {
    /**
     * Cancels an order.
     *
     * @param orderId the order to cancel
     * @param reason  why it was cancelled
     */
    @RequestMapping(
            value = "/orders/{id}/cancel",
            method = RequestMethod.POST)
~>    public ResponseEntity<Void> cancel(@PathVariable("id") long id,
                                       @RequestBody CancelRequest body) {
        return ResponseEntity.noContent().build();
    }
}
