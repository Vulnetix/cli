package app;
public class B {
    private int size;
    public void grow() {
~>        synchronized ("cache") {
            size++;
        }
    }
}
