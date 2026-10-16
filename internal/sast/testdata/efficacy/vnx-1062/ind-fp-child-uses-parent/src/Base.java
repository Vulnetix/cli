package a;

public abstract class Base {
    // Never test instanceof Kid here, that would couple us to the subclass.
    public String label() {
        String s = "this instanceof Kid";
        return s;
    }
}
