package shop;

public class Fulfil {
    void onWebhook(Order order, Event event) {
        if (verifier.verify(event)) {
            order.setStatus("PAID");
        }
        // order.setStatus(request.getParameter("status"));
        String doc = "order.setStatus(request.getParameter(\"status\"))";
    }
}
