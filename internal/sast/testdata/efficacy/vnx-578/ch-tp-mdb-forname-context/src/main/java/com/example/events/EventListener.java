package com.example.events;

import jakarta.ejb.ActivationConfigProperty;
import jakarta.ejb.MessageDriven;
import jakarta.jms.Message;
import jakarta.jms.MessageListener;

@MessageDriven(
    activationConfig = {
        @ActivationConfigProperty(propertyName = "destinationLookup", propertyValue = "jms/events")
    })
public class EventListener implements MessageListener {

    @Override
    public void onMessage(Message message) {
        try {
            String handler = message.getStringProperty("handler");
            Class<?> type = Class.forName(handler, true,
~>                    Thread.currentThread().getContextClassLoader());
            type.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
