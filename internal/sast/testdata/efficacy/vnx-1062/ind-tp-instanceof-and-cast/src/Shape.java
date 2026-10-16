package geo;

public abstract class Shape {
    public double area() {
~>        if (this instanceof Circle) {
~>            return ((Circle) this).radius() * 3.14;
        }
        return 0;
    }
}
