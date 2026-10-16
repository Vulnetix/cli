package fleet;

public abstract class Vehicle {
    public boolean sameKind(Vehicle other) {
~>        return getClass() == Truck.class && other.getClass() == Truck.class;
    }

    public static Vehicle heavy() {
~>        return new Truck(18);
    }
}
