package com.acme.checkout;

import javax.enterprise.context.Conversation;
import javax.enterprise.context.ConversationScoped;
import javax.inject.Inject;
import javax.inject.Named;

@Named
@ConversationScoped
~>public class CheckoutFlow implements Cloneable {

    @Inject
    private Conversation conversation;

    private String shippingOption;

    public void begin() {
        if (conversation.isTransient()) {
            conversation.begin();
        }
    }

    public void finish() {
        conversation.end();
    }
}
