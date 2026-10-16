package com.acme.events;

import java.io.InputStream;
import javax.ejb.ActivationConfigProperty;
import javax.ejb.MessageDriven;
import javax.jms.Message;
import javax.jms.MessageListener;

@MessageDriven(activationConfig = {
    @ActivationConfigProperty(propertyName = "destinationLookup", propertyValue = "jms/audit")
})
public class AuditListener implements MessageListener {
    @Override
    public void onMessage(Message message) {
~>        InputStream schema = getClass().getClassLoader().getResourceAsStream("audit-schema.xsd");
        validate(message, schema);
    }

    private void validate(Message m, InputStream s) { }
}
