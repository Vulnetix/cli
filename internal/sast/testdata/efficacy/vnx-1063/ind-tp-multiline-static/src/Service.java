package svc;

public class Service {
    private static PaymentGateway gateway;

    static
    {
        try {
~>            gateway = new PaymentGateway(
                System.getenv("GW_URL"));
        } catch (RuntimeException e) {
            throw new IllegalStateException("no gateway", e);
        }
    }
}
