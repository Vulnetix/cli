public class Foo {
    void close() {
        // delete this;
        this.release();
    }
    void release() { }
}
