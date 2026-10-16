package shop;

// @Entity
// public class Ghost {}

public interface Misc {
    record Point(int x, int y) {}
    enum Kind { A, B }
}
