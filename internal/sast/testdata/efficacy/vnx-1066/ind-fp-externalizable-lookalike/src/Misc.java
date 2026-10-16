package m;

import java.io.Externalizable;

public class Misc implements Externalizable {
    public void writeExternal(java.io.ObjectOutput o) { }
    public void readExternal(java.io.ObjectInput i) { }
}

class UsesHelper implements SerializableHelper {
}

class Child extends Customer {
    // class Fake implements Serializable
    String s = "implements Serializable";
}
