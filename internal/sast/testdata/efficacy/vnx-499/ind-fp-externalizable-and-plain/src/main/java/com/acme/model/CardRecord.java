package com.acme.model;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class CardRecord implements Externalizable {
    private String cardNumber;
    private String last4;

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeUTF(last4);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        last4 = in.readUTF();
    }
}
