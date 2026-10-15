package com.acme.ws.client;

import java.net.URL;
import javax.xml.namespace.QName;
~>import javax.xml.ws.Service;
~>import javax.xml.ws.WebEndpoint;
~>import javax.xml.ws.WebServiceClient;
~>import javax.annotation.Generated;

@Generated(value = "com.sun.tools.ws.WsImport", date = "2019-04-02T10:11:12")
@WebServiceClient(name = "PaymentService", targetNamespace = "http://acme.com/pay")
public class PaymentService extends Service {

    public PaymentService(URL wsdl, QName name) {
        super(wsdl, name);
    }

    @WebEndpoint(name = "PaymentPort")
    public PaymentPort getPaymentPort() {
        return super.getPort(new QName("http://acme.com/pay", "PaymentPort"), PaymentPort.class);
    }
}
