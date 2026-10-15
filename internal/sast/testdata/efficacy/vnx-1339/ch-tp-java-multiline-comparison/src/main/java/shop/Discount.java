package shop;

public final class Discount {
    public static boolean isTenPercent(double rate) {
        return rate
~>            == 0.1;
    }

    public static boolean isHalf(double rate) {
        return rate == 0.5;
    }
}
